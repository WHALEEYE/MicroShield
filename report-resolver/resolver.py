import json
import os
import time
from enum import Enum

import yaml

import templates

LABEL_PREFIX = "kubernetes_labels_"
NAME_KEY = "kubernetes_name"
NAMESPACE_KEY = "kubernetes_namespace"
SERVICE_SELECTOR = "kubernetes_selector"
K8S_NS_LABEL = "kubernetes.io/metadata.name"


class Pod:
    """
    Represents a pod.
    """

    def __init__(self, name, labels, namespace):
        self.name = name
        self.labels = labels
        self.namespace = namespace

    def __eq__(self, other):
        return self.name == other.name and self.namespace == other.namespace


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, pod_name, pod_labels, namespace, deployment_name):
        deployment_part = f"-{deployment_name}" if deployment_name else ""
        self.name = f"{pod_name}{deployment_part}-{namespace}-networkpolicy"
        self.template = templates.policy_template(self.name, namespace, pod_labels, False)
        self.rules = {}

    def add_rule(self, direction, outside_pod_id, outside_pod_info, port):
        if outside_pod_id not in self.rules:
            self.rules[outside_pod_id] = Rule(direction, outside_pod_info, port)
        elif port not in self.rules[outside_pod_id].ports:
            self.rules[outside_pod_id].add_port(port)

    def generate_yaml(self):
        if not self.rules:
            return None
        for pod_id, rule in self.rules.items():
            is_ingress = rule.direction == Direction.INGRESS
            rule_frame = templates.rule_template(is_ingress)
            pod_selector = rule_frame["from" if is_ingress else "to"][0]
            pod_selector["namespaceSelector"]["matchLabels"][K8S_NS_LABEL] = rule.outside_pod_ns
            pod_selector["podSelector"]["matchLabels"] = rule.outside_pod_labels
            for port in rule.ports:
                rule_frame["ports"].append({"port": port})
            self.template["spec"]["ingress" if is_ingress else "egress"].append(rule_frame)
        return yaml.dump(self.template)


class Direction(Enum):
    INGRESS = 1
    EGRESS = 2


class Rule:

    def __init__(self, direction, outside_pod_info, port):
        self.direction = direction
        self.outside_pod_labels = outside_pod_info.labels
        self.outside_pod_ns = outside_pod_info.namespace
        self.ports = [port]

    def add_port(self, port):
        self.ports.append(port)

    def __eq__(self, other):
        return self.direction == other.direction and self.outside_pod_labels == other.outside_pod_labels and \
               self.outside_pod_ns == other.outside_pod_ns and self.ports == other.ports


def get_port_from_enp_id(enp_id):
    return int(enp_id.split(";")[-1])


def get_parent_id(info, parent_type):
    if "parents" in info and info["parents"] is not None:
        if parent_type in info["parents"]:
            return info["parents"][parent_type][0]
    return None


def parse_label(latest_info):
    """
    Parse the label string to a dictionary.
    """
    labels = {}
    for key, value in latest_info.items():
        if key.startswith(LABEL_PREFIX):
            labels[key[len(LABEL_PREFIX):]] = value["value"]
    return labels


def analyze_report(report):
    process_to_pod = {}
    enp_to_pod = {}
    enp_to_adj = {}
    pod_id_to_info = {}

    policies = {}

    enps = report["Endpoint"]["nodes"]
    procs = report["Process"]["nodes"]
    ctns = report["Container"]["nodes"]
    pods = report["Pod"]["nodes"]
    deps = report["Deployment"]["nodes"]

    for proc_id, proc_info in procs.items():
        parent_ctn_id = get_parent_id(proc_info, "container")
        if parent_ctn_id not in ctns:
            continue
        parent_pod_id = get_parent_id(ctns[parent_ctn_id], "pod")
        if parent_pod_id not in pods:
            continue
        process_to_pod[proc_id] = parent_pod_id

    for enp_id, enp_info in enps.items():
        enp_to_adj[enp_id] = enp_info["adjacency"] if "adjacency" in enp_info else []
        if "latest" not in enp_info:
            continue
        enp_latest = enp_info["latest"]
        if "host_node_id" not in enp_latest or "pid" not in enp_latest:
            continue
        host_id = enp_latest["host_node_id"]["value"].split(";")[0]
        pid = enp_latest["pid"]["value"]
        proc_id = host_id + ";" + pid
        if proc_id not in process_to_pod:
            continue
        enp_to_pod[enp_id] = process_to_pod[proc_id]

    for pod_id, pod_info in pods.items():
        pod_latest = pod_info["latest"]
        labels = parse_label(pod_latest)
        namespace = pod_latest[NAMESPACE_KEY]["value"]
        pod_name = pod_latest[NAME_KEY]["value"]
        prt_dep_id = get_parent_id(pods[pod_id], "deployment")
        prt_dep_name = None
        if prt_dep_id in deps and "latest" in deps[prt_dep_id]:
            prt_dep_name = deps[prt_dep_id]["latest"]["kubernetes_name"]["value"]
        pod_id_to_info[pod_id] = Pod(pod_name, labels, namespace)
        policies[pod_id] = Policy(pod_name, labels, namespace, prt_dep_name)

    for enp_id, pod_id in enp_to_pod.items():
        adj_enps = enp_to_adj[enp_id]
        for adj_enp_id in adj_enps:
            if adj_enp_id not in enp_to_pod:
                continue
            adj_pod_id = enp_to_pod[adj_enp_id]
            if adj_pod_id == pod_id:
                continue
            policies[pod_id].add_rule(Direction.EGRESS, adj_pod_id, pod_id_to_info[adj_pod_id],
                                      get_port_from_enp_id(adj_enp_id))
            policies[adj_pod_id].add_rule(Direction.INGRESS, pod_id, pod_id_to_info[pod_id],
                                          get_port_from_enp_id(adj_enp_id))

    policy_yamls = {}
    for policy in policies.values():
        if policy.rules:
            policy_yamls[policy.name] = policy.generate_yaml()

    return policy_yamls


if __name__ == "__main__":
    start_time = time.time()
    # create folder named "policies" if not exist
    if not os.path.exists("policies"):
        os.makedirs("policies")
    # delete all files in the folder
    for file in os.listdir("policies"):
        os.remove(os.path.join("policies", file))
    report = json.load(open("report.json"))
    files = analyze_report(report)
    for name, content in files.items():
        with open("policies/" + name + ".yaml", "w") as f:
            f.write(content)
    print("Time used: " + str(time.time() - start_time))
