import json
import os

import yaml

import templates

FLOW_FILE = "../data/flows.json"
K8S_NS_LABEL = "kubernetes.io/metadata.name"


class Direction(enumerate):
    INGRESS = 0
    EGRESS = 1


class ServiceEnd:
    def __init__(self, svc_id, svc_name, ns, ip, port, selectors):
        self.svc_id = svc_id
        self.svc_name = svc_name
        self.ns = ns
        self.ip = ip
        self.port = port
        self.selectors = selectors


class Flow:
    def __init__(self, src, dst, direction):
        self.src = src
        self.dst = dst
        self.direction = direction
        self.activated = False
        self.linked_rule = None

    def link_rule(self, rule):
        self.linked_rule = rule

    def activate(self):
        if self.activated:
            return
        self.activated = True
        if self.linked_rule is not None:
            self.linked_rule.activate()

    def deactivate(self):
        if not self.activated:
            return
        self.activated = False
        if self.linked_rule is not None:
            self.linked_rule.deactivate()


class Policy:
    def __init__(self, name, pod_selector):
        self.template = templates.policy_template(name, namespace, pod_selector, allow_dns)
        self.name = name
        self.linked_rules = []
        self.activate_count = 0

    def generate_yaml(self):
        for rule in self.linked_rules:
            if not rule.activated:
                continue
            rule_frame = templates.rule_template(rule.direction == Direction.INGRESS)
            ingress = rule.direction == Direction.INGRESS
            pod_selector = rule_frame["from" if ingress else "to"][0]
            pod_selector["namespaceSelector"]["matchLabels"][K8S_NS_LABEL] = rule.ns
            pod_selector["podSelector"]["matchLabels"] = rule.pod_labels
            rule_frame["ports"][0]["port"] = rule.port
            self.template["spec"]["ingress" if ingress else "egress"].append(rule_frame)
        return yaml.dump(self.template)

    def link_rule(self, rule):
        self.linked_rules.append(rule)


class Rule:
    def __init__(self, direction, ns, pod_labels, cidr, port, svc_id, pod_selector):
        self.direction = direction
        self.ns = ns
        self.pod_labels = pod_labels
        self.cidr = cidr
        self.port = port
        self.svc_id = svc_id
        self.pod_selector = pod_selector
        self.activated = False
        self.linked_flows = []
        self.linked_policy = None

    def link_flow(self, flow):
        self.linked_flows.append(flow)

    def link_policy(self, policy):
        self.linked_policy = policy

    def activate(self):
        if self.activated:
            return
        self.activated = True
        if self.linked_policy is not None:
            self.linked_policy.activate_count += 1
        for flow in self.linked_flows:
            flow.activate()

    def deactivate(self):
        if not self.activated:
            return
        self.activated = False
        if self.linked_policy is not None:
            self.linked_policy.activate_count -= 1
        for flow in self.linked_flows:
            flow.deactivate()


def add_flow(flow_info, direction, src_id, dst_id):
    global aggregated_flows
    if (direction, src_id, dst_id) in existing_flow_keys:
        return
    else:
        src_svc = flow_info["src"]["service"]
        dst_svc = flow_info["dst"]["service"]
        src_svc_selectors = {}
        if "selector" in src_svc:
            src_selectors = src_svc["selector"].split(",")
            for sel in src_selectors:
                key, value = sel.split("=")
                src_svc_selectors[key] = value
        dst_svc_selectors = {}
        if "selector" in dst_svc:
            dst_selectors = dst_svc["selector"].split(",")
            for sel in dst_selectors:
                key, value = sel.split("=")
                dst_svc_selectors[key] = value
        src = ServiceEnd(src_id, src_svc["name"], src_svc["namespace"], flow_info["tuple"]["src_addr"],
                         flow_info["tuple"]["src_port"], src_svc_selectors)
        dst = ServiceEnd(dst_id, dst_svc["name"], dst_svc["namespace"], flow_info["tuple"]["dst_addr"],
                         flow_info["tuple"]["dst_port"], dst_svc_selectors)
        aggregated_flows.append(Flow(src, dst, direction))
        existing_flow_keys.append((direction, src_id, dst_id))


def aggregate_policy():
    if all_pods:
        policies["all"] = Policy(policy_name, {})
        for rule in aggregated_rules:
            policies["all"].link_rule(rule)
            rule.link_policy(policies["all"])
    else:
        for rule in aggregated_rules:
            if rule.svc_id not in policies:
                policies[rule.svc_id] = Policy(f"{policy_name}-{rule.svc_id[0:4]}", rule.pod_selector)
            policies[rule.svc_id].link_rule(rule)
            rule.linked_policy = policies[rule.svc_id]


def aggregate_rule():
    for flow in aggregated_flows:
        if flow.linked_rule is None:
            ns = flow.src.ns if flow.direction == Direction.INGRESS else flow.dst.ns
            pod_labels = flow.src.selectors if flow.direction == Direction.INGRESS else flow.dst.selectors
            svc = flow.src.svc_name if flow.direction == Direction.INGRESS else flow.dst.svc_name
            pod_selector = flow.dst.selectors if flow.direction == Direction.INGRESS else flow.src.selectors
            svc_id = flow.dst.svc_id if flow.direction == Direction.INGRESS else flow.src.svc_id
            rule = Rule(flow.direction, ns, pod_labels, None, flow.dst.port, svc_id, pod_selector)
            rule.link_flow(flow)
            flow.link_rule(rule)
            aggregated_rules.append(rule)
            if all_pods:
                for t_flow in aggregated_flows:
                    if t_flow == flow:
                        continue
                    temp_svc = t_flow.src.svc_name if t_flow.direction == Direction.INGRESS else t_flow.dst.svc_name
                    if t_flow.direction == flow.direction and t_flow.dst.port == rule.port and temp_svc == svc:
                        rule.link_flow(t_flow)
                        t_flow.link_rule(rule)


def aggregate_flow():
    for flow in records:
        flow = flow.strip()
        flow_dict = json.loads(flow)
        src = flow_dict["src"]
        dst = flow_dict["dst"]
        if src["service"] and dst["service"]:
            if src["service"]["namespace"] == namespace:
                add_flow(flow_dict, Direction.EGRESS, src["service"]["id"], dst["service"]["id"])
            if dst["service"]["namespace"] == namespace:
                add_flow(flow_dict, Direction.INGRESS, src["service"]["id"], dst["service"]["id"])
        else:
            continue
    aggregate_rule()
    aggregate_policy()


def generate_policy_yaml():
    policy_yamls = {}
    for policy in policies.values():
        if policy.activate_count > 0:
            policy_yamls[policy.name] = policy.generate_yaml()
    if not os.path.exists(f"./policies/{policy_name}"):
        os.makedirs(f"./policies/{policy_name}")
    else:
        # delete existing yaml files
        for file in os.listdir(f"./policies/{policy_name}"):
            os.remove(f"./policies/{policy_name}/{file}")
    for yaml_name, yaml_content in policy_yamls.items():
        with open(f"./policies/{policy_name}/{yaml_name}.yaml", "w") as yaml_file:
            yaml_file.write(yaml_content)


def display():
    print(f"     {'Direction':20} {'Source':20} {'Destination':20} #")
    for index, flow in enumerate(aggregated_flows):
        mark = "*" if flow.activated else " "
        direction_str = "Ingress" if flow.direction == Direction.INGRESS else "Egress"
        print(f"[{mark}]  {direction_str:20} {flow.src.svc_name:20} {flow.dst.svc_name:20} {index}")


if __name__ == "__main__":
    existing_flow_keys = []
    aggregated_flows = []
    aggregated_rules = []
    policies = {}
    with open(FLOW_FILE, "r", encoding='utf8') as f:
        records = f.readlines()
    namespace = input("Enter namespace: ")
    policy_name = input("Enter policy name: ")
    all_pods = input("All Pods? (\033[36my\033[0m/n): ") != "n"
    allow_dns = input("Allow DNS? (\033[36my\033[0m/n): ") != "n"
    aggregate_flow()

    display()
    while True:
        command = input("Enter operation: ")
        op = command.split()
        if op[0] == "s":
            aggregated_flows[int(op[1])].activate()
        elif op[0] == "c":
            aggregated_flows[int(op[1])].deactivate()
        elif op[0] == "g":
            generate_policy_yaml()
            break
        display()
