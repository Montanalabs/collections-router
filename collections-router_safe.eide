#! Collections router — untrusted an account can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires routeCollection — the collections router sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant routeCollection

type CollStage = Reminder | Notice | LegalC
type Decision = RouteColl(CollStage) | HoldColl

let raw = fetch<web>  # UNTRUSTED an account — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { routeCollection(d) }  # act on the trusted decision only
