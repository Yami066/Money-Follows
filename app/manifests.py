"""Declared roles. IAM scopes are deliberately broad (as in real deployments); the manifest is what the role is FOR."""

ALL_TOOLS = ["search_suppliers", "list_documents", "read_document", "create_purchase_request", "get_budget",
             "read_hr_file", "send_email", "http_post", "delegate"]

MANIFESTS = {
    "procurement": {
        "name": "Procurement Agent", "owner": "ops-lead@mockcorp.internal", "cohort": "procurement",
        "purpose": "Compare supplier prices and create purchase requests",
        "tools": ["search_suppliers", "list_documents", "read_document", "create_purchase_request", "send_email"],
        "domains": ["suppliers", "documents", "purchasing", "comms"],
        "egress": ["mockcorp.internal", "acme-metals.example", "nordic-fasteners.example", "brightline.example"],
        "can_delegate": ["finance"],
    },
    "hr": {
        "name": "HR Agent", "owner": "hr-lead@mockcorp.internal", "cohort": "hr",
        "purpose": "Answer HR questions and prepare internal HR summaries",
        "tools": ["read_hr_file", "send_email"],
        "domains": ["hr", "comms"],
        "egress": ["mockcorp.internal"],
        "can_delegate": [],
    },
    "finance": {
        "name": "Finance Agent", "owner": "cfo@mockcorp.internal", "cohort": "finance",
        "purpose": "Report budgets and vendor spend to internal finance staff",
        "tools": ["get_budget", "list_documents", "read_document", "send_email"],
        "domains": ["finance", "documents", "comms"],
        "egress": ["mockcorp.internal"],
        "can_delegate": [],
    },
    "orchestrator": {
        "name": "Orchestrator Agent", "owner": "platform@mockcorp.internal", "cohort": "orchestrator",
        "purpose": "Route incoming requests to the right specialist agent",
        "tools": ["delegate"],
        "domains": ["delegation"],
        "egress": ["mockcorp.internal"],
        "can_delegate": ["procurement", "hr", "finance"],
    },
}

# Normal work used to build each role's history (the learned baseline before the demo starts)
HISTORY = {
    "procurement": [
        [("list_documents", {}), ("read_document", {"name": "quote_acme_q4.pdf"}), ("read_document", {"name": "quote_nordic_q4.pdf"}),
         ("search_suppliers", {"item": "steel bolts"}),
         ("create_purchase_request", {"supplier": "Acme Metals"}), ("send_email", {"to": "sales@acme-metals.example"})],
        [("search_suppliers", {"item": "hex nuts"}), ("read_document", {"name": "quote_nordic_q4.pdf"}),
         ("create_purchase_request", {"supplier": "Nordic Fasteners"}), ("send_email", {"to": "orders@nordic-fasteners.example"})],
        [("read_document", {"name": "policy_procurement.pdf"}), ("search_suppliers", {"item": "steel bolts"}),
         ("read_document", {"name": "quote_nordic_q4.pdf"}), ("create_purchase_request", {"supplier": "Nordic Fasteners"}),
         ("send_email", {"to": "ops-lead@mockcorp.internal"})],
    ],
    "hr": [
        [("read_hr_file", {"name": "reviews_2026.csv"}), ("send_email", {"to": "hr-lead@mockcorp.internal"})],
        [("read_hr_file", {"name": "salaries_2026.csv"}), ("send_email", {"to": "hr-lead@mockcorp.internal"})],
    ],
    "finance": [
        [("get_budget", {"department": "operations"}), ("send_email", {"to": "cfo@mockcorp.internal"})],
        [("list_documents", {}), ("read_document", {"name": "vendor_payments_q3.pdf"}), ("send_email", {"to": "cfo@mockcorp.internal"})],
    ],
    "orchestrator": [
        [("delegate", {"agent": "procurement"})], [("delegate", {"agent": "hr"})], [("delegate", {"agent": "finance"})],
    ],
}
