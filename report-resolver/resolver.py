import copy
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
UUID_KEY = "kubernetes_cluster_uuid"
IGNORED_LABELS = ["controller-revision-hash", "statefulset.kubernetes.io/pod-name"]


def debug_info(info):
    if debug:
        print(f"\033[35m[DEBUG] {info}\033[0m")


def label_matched(conditions, labels):
    for key, value in conditions.items():
        if key not in labels or labels[key] != value:
            return False
    return True


class ResourceInfo:

    def __init__(self, resource_name, labels, namespace):
        self.name = resource_name
        self.labels = labels
        self.namespace = namespace

    def __eq__(self, other):
        return self.name == other.name and self.namespace == other.namespace


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, resource_name, inside_labels, namespace, resource_type):
        self.name = f"{resource_type.name.lower()}-{resource_name}-{namespace}"
        self.inside_labels = inside_labels
        self.namespace = namespace
        self.rules = {}

    def add_rule(self, direction, outside_resource_id, outside_resource_info, port):
        if outside_resource_id not in self.rules:
            self.rules[outside_resource_id] = Rule(direction, outside_resource_info, port)
        else:
            self.rules[outside_resource_id].add_port(port)

    def generate_yaml(self):
        if not self.rules:
            return None
        template = templates.policy_template(self.name, self.namespace, self.inside_labels, False)
        for pod_id, rule in self.rules.items():
            is_ingress = rule.direction == Direction.INGRESS
            rule_frame = templates.rule_template(is_ingress)
            pod_selector = rule_frame["from" if is_ingress else "to"][0]
            pod_selector["namespaceSelector"]["matchLabels"][K8S_NS_LABEL] = rule.outside_resource_ns
            pod_selector["podSelector"]["matchLabels"] = rule.outside_resource_labels
            for port in rule.ports:
                rule_frame["ports"].append({"port": port})
            template["spec"]["ingress" if is_ingress else "egress"].append(rule_frame)
        return yaml.dump(template)

    def merge(self, other_policy):
        if self.name != other_policy.name:
            raise ValueError("Cannot merge policies with different names")
        for rule_id, rule in other_policy.rules.items():
            if rule_id in self.rules:
                for port in rule.ports:
                    self.rules[rule_id].add_port(port)
            else:
                self.rules[rule_id] = rule

    @staticmethod
    def read_from_dict(policy_dict):
        metadata = policy_dict["metadata"]
        spec = policy_dict["spec"]
        policy_name = metadata["name"]
        resource_type = ResourceType[(policy_name.split("-")[0]).upper()]
        policy = Policy("", spec["podSelector"]["matchLabels"], metadata["namespace"], resource_type)
        policy.name = policy_name
        for rule in spec["ingress"]:
            for pod in rule["from"]:
                pod_labels = pod["podSelector"]["matchLabels"]
                pod_ns = pod["namespaceSelector"]["matchLabels"][K8S_NS_LABEL]
                for port in rule["ports"]:
                    policy.add_rule(Direction.INGRESS, policy_name, ResourceInfo("", pod_labels, pod_ns),
                                    port["port"])
        for rule in spec["egress"]:
            for pod in rule["to"]:
                pod_labels = pod["podSelector"]["matchLabels"]
                pod_ns = pod["namespaceSelector"]["matchLabels"][K8S_NS_LABEL]
                for port in rule["ports"]:
                    policy.add_rule(Direction.EGRESS, policy_name, ResourceInfo("", pod_labels, pod_ns),
                                    port["port"])
        return policy


class Direction(Enum):
    INGRESS = 1
    EGRESS = 2


class ResourceType(Enum):
    POD = 1
    DEPLOYMENT = 2


class Rule:

    def __init__(self, direction, outside_resource_info, port):
        self.direction = direction
        self.outside_resource_labels = outside_resource_info.labels
        self.outside_resource_ns = outside_resource_info.namespace
        self.ports = [port]

    def add_port(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def __eq__(self, other):
        return self.direction == other.direction and self.outside_resource_labels == other.outside_resource_labels and \
               self.outside_resource_ns == other.outside_resource_ns and self.ports == other.ports

    def rule_condition_matched(self, other_rule):
        return label_matched(self.outside_resource_labels, other_rule.outside_resource_labels) and \
               self.outside_resource_ns == other_rule.outside_resource_ns


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
            label_name = key[len(LABEL_PREFIX):]
            if label_name in IGNORED_LABELS:
                continue
            labels[key[len(LABEL_PREFIX):]] = value["value"]
    return labels


def assemble_proc_id(host_node_id, pid):
    host_id = host_node_id.split(";")[0]
    return host_id + ";" + pid


def compare(static_policy_dicts, dynamic_policies):
    static_policies = {}
    for policy_dict in static_policy_dicts:
        policy = Policy.read_from_dict(policy_dict)
        static_policies[policy.name] = policy

    abnormal_policies = []

    for policy_name, policy in dynamic_policies.items():
        if not policy.rules:
            continue
        if policy_name not in static_policies:
            abnormal_policies.append(policy)
            continue
        static_policy = static_policies[policy_name]
        abnormal_policy = copy.deepcopy(policy)
        abnormal_policy.rules = {}
        for dynamic_rule in policy.rules.values():
            matched_rule = None
            for static_rule in static_policy.rules.values():
                if dynamic_rule.rule_condition_matched(static_rule):
                    matched_rule = static_rule
                    break
            if matched_rule is None:
                abnormal_policy.rules[hash(str(dynamic_rule.outside_resource_labels))] = dynamic_rule
                continue
            abnormal_rule = copy.deepcopy(dynamic_rule)
            abnormal_rule.ports = [port for port in dynamic_rule.ports if port not in matched_rule.ports]
            if abnormal_rule.ports:
                abnormal_policy.rules[hash(str(dynamic_rule.outside_resource_labels))] = abnormal_rule
        if abnormal_policy.rules:
            abnormal_policies.append(abnormal_policy)

    return abnormal_policies


def analyze_report(report, uuid):
    process_to_pod = {}
    enp_to_pod = {}
    enp_to_adj = {}
    pod_id_to_rsc_id = {}
    resource_id_to_info = {}

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
        prt_pod_id = get_parent_id(ctns[parent_ctn_id], "pod")
        if prt_pod_id not in pods:
            continue
        if pods[prt_pod_id]["latest"][UUID_KEY]["value"] != uuid:
            continue
        process_to_pod[proc_id] = prt_pod_id

    for enp_id, enp_info in enps.items():
        enp_to_adj[enp_id] = enp_info["adjacency"] if "adjacency" in enp_info else []
        if "latest" not in enp_info:
            continue
        enp_latest = enp_info["latest"]
        if "host_node_id" not in enp_latest or "pid" not in enp_latest:
            continue
        proc_id = assemble_proc_id(enp_latest["host_node_id"]["value"], enp_latest["pid"]["value"])
        if proc_id not in process_to_pod:
            continue
        enp_to_pod[enp_id] = process_to_pod[proc_id]

    for pod_id, pod_info in pods.items():
        pod_latest = pod_info["latest"]
        labels = parse_label(pod_latest)
        namespace = pod_latest[NAMESPACE_KEY]["value"]
        pod_name = pod_latest[NAME_KEY]["value"]
        prt_dep_id = get_parent_id(pods[pod_id], "deployment")
        resource_name = pod_name
        resource_id = pod_id
        resource_type = ResourceType.POD
        if prt_dep_id in deps and "latest" in deps[prt_dep_id]:
            resource_id = prt_dep_id
            resource_type = ResourceType.DEPLOYMENT
            resource_name = deps[prt_dep_id]["latest"][NAME_KEY]["value"]
        pod_id_to_rsc_id[pod_id] = resource_id
        if resource_id not in resource_id_to_info:
            resource_id_to_info[resource_id] = ResourceInfo(resource_name, labels, namespace)
        policies[resource_id] = Policy(resource_name, labels, namespace, resource_type)

    for enp_id, pod_id in enp_to_pod.items():
        adj_enps = enp_to_adj[enp_id]
        for adj_enp_id in adj_enps:
            if adj_enp_id not in enp_to_pod:
                continue
            adj_pod_id = enp_to_pod[adj_enp_id]
            if adj_pod_id == pod_id:
                continue
            adj_rsc_id = pod_id_to_rsc_id[adj_pod_id]
            rsc_id = pod_id_to_rsc_id[pod_id]
            policies[rsc_id].add_rule(Direction.EGRESS, adj_rsc_id, resource_id_to_info[adj_rsc_id],
                                      get_port_from_enp_id(adj_enp_id))
            policies[adj_rsc_id].add_rule(Direction.INGRESS, rsc_id, resource_id_to_info[rsc_id],
                                          get_port_from_enp_id(adj_enp_id))

    aggregated_policies = {}
    for policy in policies.values():
        if policy.name in aggregated_policies:
            aggregated_policies[policy.name].merge(policy)
        else:
            aggregated_policies[policy.name] = policy
    return aggregated_policies


def output_policies_to_dir(policies, dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    # delete all files in the folder
    for file in os.listdir(dir_path):
        os.remove(os.path.join(dir_path, file))
    for policy in policies:
        yaml_content = policy.generate_yaml()
        if yaml_content is not None:
            with open(f"{dir_path}/" + policy.name + ".yaml", "w") as f:
                f.write(yaml_content)


def generate_dynamic_policies(report, uuid):
    policies = analyze_report(report, uuid)
    output_policies_to_dir(policies.values(), "policies")


def detect_abnormal_conn(static_policy_dicts, report, uuid):
    policies = analyze_report(report, uuid)
    abnormal_policies = compare(static_policy_dicts, policies)
    output_policies_to_dir(abnormal_policies, "abnormal_policies")


if __name__ == "__main__":
    debug = False
    start_time = time.time()
    TEST_DATA_DIR = os.path.abspath(os.path.join(__file__, os.pardir, "test_data"))
    # create folder named "policies" if not exist
    test_uuid = "33d1901faed141cf8ccacf5e94961607"
    test_report = json.load(open(f"{TEST_DATA_DIR}/report.json"))
    test_static_policies = []
    for test_static_file in os.listdir(f"{TEST_DATA_DIR}/static_policies"):
        test_static_policies.append(
            yaml.safe_load(open(os.path.join(f"{TEST_DATA_DIR}/static_policies", test_static_file))))
    detect_abnormal_conn(test_static_policies, test_report, test_uuid)
    print("Time used: " + str(time.time() - start_time))
