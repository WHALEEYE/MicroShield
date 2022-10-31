import argparse
import json
import os

import yaml

import templates


class Direction(enumerate):
    INGRESS = 0
    EGRESS = 1


class Granularity(enumerate):
    NAMESPACE = 0
    SERVICE = 1
    POD = 2


class ConnEnd:
    """
    Represents a connection endpoint, containing ID, name, namespace, IP, port and selector.
    The IP is used to describe the endpoints outside the cluster (CIDR), which is not used in the current version.
    """

    def __init__(self, end_id, name, ns, ip, port, selectors):
        self.end_id = end_id
        self.name = name
        self.ns = ns
        self.ip = ip
        self.port = port
        self.selectors = selectors


class Connection:
    """
    Represents a connection, containing source and destination service endpoints, and direction.
    """

    def __init__(self, inside_end, svc_end, direction):
        self.inside_end = inside_end
        self.svc_end = svc_end
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


class Rule:
    """
    Represents a rule, containing direction, namespace, selectors, CIDR, port, inside resource name and pod selector.

    Note that the service selectors here represent the pod selectors in entry,
    while the inside selectors represent which pod(s) in the namespace should this rule applied to.

    The inside name is used to identify the inside resource according to the granularity, so it could be the name of
    the namespace, service or pod.
    """

    def __init__(self, direction, ns, svc_selector, inside_selector, cidr, port, inside_name):
        self.direction = direction
        self.ns = ns
        self.svc_selector = svc_selector
        self.inside_selector = inside_selector
        self.cidr = cidr
        self.port = port
        self.inside_name = inside_name
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
            pod_selector["podSelector"]["matchLabels"] = rule.svc_selector
            rule_frame["ports"][0]["port"] = rule.port
            self.template["spec"]["ingress" if ingress else "egress"].append(rule_frame)
        return yaml.dump(self.template)

    def link_rule(self, rule):
        """
        Links the policy to one rule.
        """
        self.linked_rules.append(rule)


conn_keys = []
connections = []
rules = []
policies = {}

K8S_NS_LABEL = "kubernetes.io/metadata.name"

FILE_PAR_DIR = os.path.abspath(os.path.join(__file__, os.pardir))
NAMESPACE = "default"
OUT_FOLDER_NAME = "my-policy"
GRANULARITY = Granularity.NAMESPACE
ALLOW_DNS = True
INPUT_FILE = FILE_PAR_DIR + "/../data/flows.json"


def extract_selectors(info):
    """
    Extracts selectors from the info of services.

    Args:
        info: The service's info map.

    Returns:
        A tuple of selectors.
    """
    selectors = {}
    if "selector" in info:
        raw_selectors = info["selector"].split(",")
        for selector in raw_selectors:
            key, value = selector.split("=")
            selectors[key] = value
    return selectors


def add_conn(direction, inside_info, inside_ip, inside_port, svc_info, svc_ip, svc_port):
    """
    Try to add flow into aggregated flow list.
    It will detect duplication by detecting whether there is flow with the same direction, source service ID and
    destination service ID existing in the list.
    If there is, it will stop adding the flow, so the flow list will finally contain distinct flows.
    """
    global connections
    inside_id = inside_info["id"]
    svc_id = svc_info["id"]
    if (direction, inside_id, svc_id) in conn_keys:
        return
    else:
        # If the granularity is pod, we only need to take all of this pod's labels as selectors
        inside_selectors = inside_info["labels"] if GRANULARITY == Granularity.POD else extract_selectors(inside_info)
        svc_selectors = extract_selectors(svc_info)
        inside_end = ConnEnd(inside_id, inside_info["name"], inside_info["namespace"], inside_ip, inside_port,
                             inside_selectors)
        svc_end = ConnEnd(svc_id, svc_info["name"], svc_info["namespace"], svc_ip, svc_port, svc_selectors)
        connections.append(Connection(inside_end, svc_end, direction))
        conn_keys.append((direction, inside_id, svc_id))


def aggregate_policy():
    """
    Aggregate rules into policies.
    After this method is called, each rule will be linked to one policy.
    """
    global rules, policies
    for rule in rules:
        if rule.inside_name not in policies:
            policies[rule.inside_name] = Policy(f"policy-{rule.inside_name}", rule.inside_selector)
        policies[rule.inside_name].link_rule(rule)
        rule.linked_policy = policies[rule.inside_name]


def aggregate_rule():
    """
    Aggregate connections into rules.
    After this method is called, each flow will be linked to one rule.
    """
    for conn in connections:
        if conn.linked_rule is None:
            # Some connections may already be linked in advance due to the searching process below
            port = conn.svc_end.port if conn.direction == Direction.EGRESS else conn.inside_end.port
            rule = Rule(conn.direction, conn.svc_end.ns, conn.svc_end.selectors, conn.inside_end.selectors, None,
                        port, conn.inside_end.name)
            rule.link_flow(conn)
            conn.link_rule(rule)
            rules.append(rule)
            if GRANULARITY == Granularity.NAMESPACE:
                rule.inside_name = NAMESPACE
                # search all the flows to find flows that in the same ns, and link them to the same rule
                for t_conn in connections:
                    if t_conn == conn:
                        continue
                    t_port = t_conn.svc_end.port if t_conn.direction == Direction.EGRESS else t_conn.inside_end.port
                    if t_conn.direction == conn.direction and t_port == port and t_conn.svc_end.end_id == conn.svc_end.end_id:
                        rule.link_flow(t_conn)
                        t_conn.link_rule(rule)


def aggregate_conn(flows):
    """
    Aggregate flows into connections.
    """
    for flow in flows:
        flow = flow.strip()
        flow_dict = json.loads(flow)
        src = flow_dict["src"]
        dst = flow_dict["dst"]
        # Ignore all the flows related to DNS because we already (dis)allow DNS in the policy
        if (src["service"] and src["service"]["name"] == "kube-dns") \
                or (dst["service"] and dst["service"]["name"] == "kube-dns"):
            continue
        four_tuple = flow_dict["tuple"]
        gran_str = "pod" if GRANULARITY == Granularity.POD else "service"
        if src[gran_str] and dst["service"] and src[gran_str]["namespace"] == NAMESPACE:
            # Add egress flow
            add_conn(Direction.EGRESS, src[gran_str], four_tuple["src_addr"], four_tuple["src_port"], dst["service"],
                     four_tuple["dst_addr"], four_tuple["dst_port"])
        if dst[gran_str] and src["service"] and dst[gran_str]["namespace"] == NAMESPACE:
            # Add ingress flow
            add_conn(Direction.INGRESS, dst[gran_str], four_tuple["dst_addr"], four_tuple["dst_port"], src["service"],
                     four_tuple["src_addr"], four_tuple["src_port"])
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
    inside_resource_str = "Inside Pod" if GRANULARITY == Granularity.POD else "Inside Service"
    column_width = 40 if GRANULARITY == Granularity.POD else 20
    print(f"     {'Direction':20} {inside_resource_str:{column_width}} {'Outside Service':20} #")
    for index, conn in enumerate(connections):
        mark = "*" if conn.activated else " "
        direction_str = "Ingress" if conn.direction == Direction.INGRESS else "Egress"
        print(f"[{mark}]  {direction_str:20} {conn.inside_end.name:{column_width}} {conn.svc_end.name:20} {index}")


def save_policies(policy_yamls):
    """
    Save policy YAML files to local directory.
    This is just a temporary function.
    """
    policy_folder = FILE_PAR_DIR + f"/policies/{OUT_FOLDER_NAME}"
    if not os.path.exists(policy_folder):
        os.makedirs(policy_folder)
    else:
        # delete existing yaml files
        for file in os.listdir(policy_folder):
            os.remove(f"{policy_folder}/{file}")
    for yaml_name, yaml_content in policy_yamls.items():
        with open(f"{policy_folder}/{yaml_name}.yaml", "w") as yaml_file:
            yaml_file.write(yaml_content)


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("-f", "--file", help="The file path of the flows",
                           default=FILE_PAR_DIR + "/../data/flows.json")
    arguments.add_argument("-o", "--output-folder", help="The name of the output folder")
    arguments.add_argument("-n", "--namespace", help="The namespace of the policy")
    arguments.add_argument("-g", "--granularity",
                           help="The granularity of the policy. Possible values are ns/namespace, svc/service or pod")
    arguments.add_argument("-a", "--all-policy", help="Automatically generate all possible policies",
                           action="store_true")
    arguments.add_argument("-v", "--version", help="Show version", action="version",
                           version="Policy Generator v1.1")
    arguments.add_argument("--forbid-dns", help="Forbid DNS traffic", action="store_true", default=False)
    args = arguments.parse_args()

    gran_s = input(
        "Granularity (namespace/\033[36mservice\033[0m): ") if args.granularity is None else args.granularity
    if gran_s == "namespace" or gran_s == "ns":
        GRANULARITY = Granularity.NAMESPACE
    elif gran_s == "service" or gran_s == "svc":
        GRANULARITY = Granularity.SERVICE
    elif gran_s == "pod":
        GRANULARITY = Granularity.POD
    else:
        print("Invalid granularity")
        exit(1)
    NAMESPACE = input("Enter namespace: ") if args.namespace is None else args.namespace
    OUT_FOLDER_NAME = input("Enter output folder name: ") if args.output_folder is None else args.output_folder
    ALLOW_DNS = not args.forbid_dns
    INPUT_FILE = args.file

    with open(INPUT_FILE, "r", encoding='utf8') as f:
        records = f.readlines()
    aggregate_conn(records)

    if args.all_policy:
        for connection in connections:
            connection.activate()
        save_policies(generate_policy_yaml())
        exit(0)

        # Simple display loop for user to select rules.
    display()
    while True:
        command = input("Enter operation: ")
        op = command.split()
        if op[0] == "s":
            connections[int(op[1])].activate()
        elif op[0] == "c":
            connections[int(op[1])].deactivate()
        elif op[0] == "g":
            save_policies(generate_policy_yaml())
            break
        display()
