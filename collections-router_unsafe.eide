#! VULNERABLE collections-router — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant routeCollection

let raw = fetch<web>
privileged { routeCollection(raw) }  # tainted -> tool: REJECTED
