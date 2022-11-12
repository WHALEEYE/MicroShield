"""
This file contains some templates for the policy generator.
"""


def policy_template(name, namespace, pod_selector, use_dns):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace
        },
        "spec": {
            "podSelector": {
                "matchLabels": pod_selector
            },
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [],
            "egress": [dns_template()] if use_dns else []
        },
    }


def dns_template():
    return {
        "to": [{
            "namespaceSelector": {},
            "podSelector": {
                "matchLabels": {"k8s-app": "kube-dns"}
            }
        }],
        "ports": [{"port": 53, "protocol": "UDP"}]
    }


def rule_template(is_ingress):
    return {
        "from" if is_ingress else "to": [{
            "namespaceSelector": {
                "matchLabels": {}
            },
            "podSelector": {
                "matchLabels": {}
            }
        }],
        "ports": []
    }
