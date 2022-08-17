import json
import os

import yaml

import templates


class Direction(enumerate):
    INGRESS = 0
    EGRESS = 1


class ServiceEnd:
    """
    Represents a service endpoint, containing service ID, name, namespace, IP, port and selector.
    The IP is used to describe the endpoints outside the cluster (CIDR), which is not used in the current version.
    """

    def __init__(self, svc_id, svc_name, ns, ip, port, selectors):
        self.svc_id = svc_id
        self.svc_name = svc_name
        self.ns = ns
        self.ip = ip
        self.port = port
        self.selectors = selectors


class Flow:
    """
    Represents a flow, containing source and destination service endpoints, and direction.
    """

    def __init__(self, src, dst, direction):
        self.src = src
        self.dst = dst
        self.direction = direction
        self.activated = False
        self.linked_rule = None

    def link_rule(self, rule):
        """
        Links the flow to one rule.
        Each flow can be linked to only one rule.
        """
        self.linked_rule = rule

    def activate(self):
        """
        Activates the flow, if it is not already activated.
        At the same time, activate the rule it belongs to.

        User can and can only call this method to select. The rules and policies will be activated accordingly.
        """
        if self.activated:
            return
        self.activated = True
        if self.linked_rule is not None:
            self.linked_rule.activate()

    def deactivate(self):
        """
        Deactivates the flow, if it is activated.
        At the same time, deactivate the rule it belongs to.

        User can and can only call this method to cancel. The rules and policies will be cancelled accordingly.
        """
        if not self.activated:
            return
        self.activated = False
        if self.linked_rule is not None:
            self.linked_rule.deactivate()


class Policy:
    """
    Represents a policy. Each policy object can generate a policy YAML file.
    """

    def __init__(self, name, pod_selector):
        self.template = templates.policy_template(name, NAMESPACE, pod_selector, ALLOW_DNS)
        self.name = name
        self.linked_rules = []
        self.activate_count = 0

    def generate_yaml(self):
        """
        Generates a policy YAML file.

        Returns:
            The YAML file as a string.
        """
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
        """
        Links the policy to one rule.
        """
        self.linked_rules.append(rule)


class Rule:
    """
    Represents a rule, containing direction, namespace, pod labels, CIDR, port, service ID and pod selector.
    Note that the pod labels here represent the pod selectors in entry,
    while the pod selectors represent which pod in the namespace should this rule applied to.
    """

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
        """
        Links the rule to one flow.
        A rule can be linked with multiple flows because flows could be aggregated.
        """
        self.linked_flows.append(flow)

    def link_policy(self, policy):
        """
        Links the rule to one policy.
        A rule can only be linked with one policy (file).
        """
        self.linked_policy = policy

    def activate(self):
        """
        Activate the rule.
        This method will only be called when a linked flow is activated.
        When a rule is activated, it will try to activate all flows it is linked to.
        """
        if self.activated:
            return
        self.activated = True
        if self.linked_policy is not None:
            self.linked_policy.activate_count += 1
        for flow in self.linked_flows:
            flow.activate()

    def deactivate(self):
        """
        Deactivate the rule.
        This method will only be called when a linked flow is deactivated.
        When a rule is deactivated, it will try to deactivate all flows it is linked to.
        """
        if not self.activated:
            return
        self.activated = False
        if self.linked_policy is not None:
            self.linked_policy.activate_count -= 1
        for flow in self.linked_flows:
            flow.deactivate()


existing_flow_keys = []
aggregated_flows = []
aggregated_rules = []
policies = {}

K8S_NS_LABEL = "kubernetes.io/metadata.name"

NAMESPACE = "default"
POLICY_NAME = "my-policy"
ALL_PODS = True
ALLOW_DNS = True


def add_flow(flow_info, direction, src_id, dst_id):
    """
    Try to add flow into aggregated flow list.
    It will detect duplication by detecting whether there is flow with the same direction, source service ID and
    destination service ID existing in the list.
    If there is, it will stop adding the flow, so the flow list will finally contain distinct flows.
    """
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
    """
    Aggregate rules into policies.
    After this method is called, each rule will be linked to one policy.
    """
    if ALL_PODS:
        policies["all"] = Policy(POLICY_NAME, {})
        for rule in aggregated_rules:
            policies["all"].link_rule(rule)
            rule.link_policy(policies["all"])
    else:
        for rule in aggregated_rules:
            if rule.svc_id not in policies:
                policies[rule.svc_id] = Policy(f"{POLICY_NAME}-{rule.svc_id[0:4]}", rule.pod_selector)
            policies[rule.svc_id].link_rule(rule)
            rule.linked_policy = policies[rule.svc_id]


def aggregate_rule():
    """
    Aggregate flows into rules.
    After this method is called, each flow will be linked to one rule.
    """
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
            if ALL_PODS:
                for t_flow in aggregated_flows:
                    if t_flow == flow:
                        continue
                    temp_svc = t_flow.src.svc_name if t_flow.direction == Direction.INGRESS else t_flow.dst.svc_name
                    if t_flow.direction == flow.direction and t_flow.dst.port == rule.port and temp_svc == svc:
                        rule.link_flow(t_flow)
                        t_flow.link_rule(rule)


def aggregate_flow(flows):
    """
    Aggregate flows into connections.
    """
    for flow in flows:
        flow = flow.strip()
        flow_dict = json.loads(flow)
        src = flow_dict["src"]
        dst = flow_dict["dst"]
        if src["service"] and dst["service"]:
            if src["service"]["namespace"] == NAMESPACE:
                add_flow(flow_dict, Direction.EGRESS, src["service"]["id"], dst["service"]["id"])
            if dst["service"]["namespace"] == NAMESPACE:
                add_flow(flow_dict, Direction.INGRESS, src["service"]["id"], dst["service"]["id"])
        else:
            continue
    aggregate_rule()
    aggregate_policy()


def generate_policy_yaml():
    """
    Check all the policies and generate yaml file for activated policy.

    Returns:
        A dict whose key is the name of the policy and value is the yaml file content.
    """
    policy_yamls = {}
    for policy in policies.values():
        if policy.activate_count > 0:
            policy_yamls[policy.name] = policy.generate_yaml()
    return policy_yamls


def display():
    """
    Display a simple panel for user to select rules.
    This is just a temporary function.
    """
    print(f"     {'Direction':20} {'Source':20} {'Destination':20} #")
    for index, flow in enumerate(aggregated_flows):
        mark = "*" if flow.activated else " "
        direction_str = "Ingress" if flow.direction == Direction.INGRESS else "Egress"
        print(f"[{mark}]  {direction_str:20} {flow.src.svc_name:20} {flow.dst.svc_name:20} {index}")


def save_policies(policy_yamls):
    """
    Save policy YAML files to local directory.
    This is just a temporary function.
    """
    if not os.path.exists(f"./policies/{POLICY_NAME}"):
        os.makedirs(f"./policies/{POLICY_NAME}")
    else:
        # delete existing yaml files
        for file in os.listdir(f"./policies/{POLICY_NAME}"):
            os.remove(f"./policies/{POLICY_NAME}/{file}")
    for yaml_name, yaml_content in policy_yamls.items():
        with open(f"./policies/{POLICY_NAME}/{yaml_name}.yaml", "w") as yaml_file:
            yaml_file.write(yaml_content)


if __name__ == "__main__":
    NAMESPACE = input("Enter namespace: ")
    POLICY_NAME = input("Enter policy name: ")
    ALL_PODS = input("All Pods? (\033[36my\033[0m/n): ") != "n"
    ALLOW_DNS = input("Allow DNS? (\033[36my\033[0m/n): ") != "n"
    with open("../data/flows.json", "r", encoding='utf8') as f:
        records = f.readlines()
    aggregate_flow(records)

    # Simple display loop for user to select rules.
    display()
    while True:
        command = input("Enter operation: ")
        op = command.split()
        if op[0] == "s":
            aggregated_flows[int(op[1])].activate()
        elif op[0] == "c":
            aggregated_flows[int(op[1])].deactivate()
        elif op[0] == "g":
            yamls = generate_policy_yaml()
            save_policies(yamls)
            break
        display()
