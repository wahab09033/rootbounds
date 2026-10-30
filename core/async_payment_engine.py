import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from core.types import (
    ErrorCode,
    RootboundSecurityException,
    PaymentStatus,
    PaymentRecord
)
from core.engine import RootboundEngine

class TransferOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    RECEIVER_PANIC = "RECEIVER_PANIC"
    OUT_OF_GAS = "OUT_OF_GAS"
    ACCOUNT_NOT_FOUND = "ACCOUNT_NOT_FOUND"

@dataclass
class InFlightPromise:
    promise_id: str
    request_id: str
    org_id: str
    agent_id: str
    recipient: str
    amount: int
    scheduled_at: int
    outcome: TransferOutcome
    callback_executed: bool = False

class AsyncPaymentEngine:
    """
    Simulates NEAR's asynchronous cross-contract promise pipeline.
    Coordinates two-phase execution:
    1. Synchronous on-chain authorization and atomic fund reservation.
    2. Asynchronous dispatch to the NEAR transfer pipeline.
    3. Safe callback execution with reservation recovery on failure.
    """

    def __init__(self, engine: RootboundEngine):
        self.engine = engine
        self.promise_queue: Dict[str, InFlightPromise] = {}
        self.settled_promises: List[InFlightPromise] = []

    def dispatch_payment_async(
        self,
        caller: str,
        org_id: str,
        agent_id: str,
        recipient: str,
        amount: int,
        request_id: str,
        nonce: int,
        intended_outcome: TransferOutcome = TransferOutcome.SUCCESS,
        timestamp: int = 0
    ) -> InFlightPromise:
        """
        Phase 1: Synchronous reservation on ROOTBOUND contract.
        Prepares asynchronous promise and places it in flight.
        """
        # Step 1: Contract validates policies and atomically reserves funds
        payment_record = self.engine.authorize_and_reserve_payment(
            caller=caller,
            org_id=org_id,
            agent_id=agent_id,
            recipient=recipient,
            amount=amount,
            request_id=request_id,
            nonce=nonce,
            timestamp=timestamp
        )

        # Step 2: Create in-flight NEAR promise
        promise_id = f"promise_{request_id}"
        promise = InFlightPromise(
            promise_id=promise_id,
            request_id=request_id,
            org_id=org_id,
            agent_id=agent_id,
            recipient=recipient,
            amount=amount,
            scheduled_at=timestamp,
            outcome=intended_outcome,
            callback_executed=False
        )
        self.promise_queue[promise_id] = promise
        return promise

    def settle_promise(self, promise_id: str, timestamp: int = 0) -> PaymentRecord:
        """
        Phase 2: Asynchronous NEAR callback handler (`on_payment_settled`).
        Executes on contract after cross-contract transfer completes or fails.
        """
        if promise_id not in self.promise_queue:
            raise RootboundSecurityException(
                ErrorCode.ERR_PAYMENT_NOT_FOUND, f"In-flight promise {promise_id} not found"
            )

        promise = self.promise_queue[promise_id]
        if promise.callback_executed:
            raise RootboundSecurityException(
                ErrorCode.ERR_INVALID_PAYMENT_STATE, f"Callback for promise {promise_id} already processed"
            )

        # Execute callback based on NEAR execution result
        if promise.outcome == TransferOutcome.SUCCESS:
            payment_record = self.engine.finalize_payment_success(
                request_id=promise.request_id,
                timestamp=timestamp
            )
        else:
            reason = f"NEAR Asynchronous Transfer Failed: {promise.outcome.value}"
            payment_record = self.engine.finalize_payment_failure(
                request_id=promise.request_id,
                reason=reason,
                timestamp=timestamp
            )

        promise.callback_executed = True
        del self.promise_queue[promise_id]
        self.settled_promises.append(promise)

        # Validate that invariant holds post-settlement
        self.engine.verify_global_invariants(promise.org_id)
        return payment_record

    def settle_all_pending(self, timestamp: int = 0) -> List[PaymentRecord]:
        """Settles all pending in-flight promises in queue."""
        results = []
        pending_ids = list(self.promise_queue.keys())
        for pid in pending_ids:
            rec = self.settle_promise(pid, timestamp=timestamp)
            results.append(rec)
        return results
