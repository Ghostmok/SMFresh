import collections
import heapq
import os
import random
from collections import defaultdict
from datetime import datetime
from itertools import combinations, permutations


path_prefix = "D:\\DB\\"

filename = ["snap-Email-Enron.txt",
            "snap-com-youtube.txt",
            "snap-cit-Patents.txt"]

subgraphs = {"snap-Email-Enron.txt":
                 {"3n3e": [{1, 3, 4}, {(1, 3), (3, 4), (1, 4)}],
                  "5n4e": [{1, 3, 4, 6, 8552}, {(1, 3), (4, 8552), (1, 4), (3, 6)}],
                  "5n6e": [{1, 3, 4, 5, 56}, {(5, 56), (3, 4), (1, 5), (1, 56), (1, 4), (1, 3)}],
                  "5n7e": [{1, 3, 4, 8552, 878}, {(3, 4), (3, 878), (1, 4), (878, 8552), (4, 8552), (3, 8552), (1, 3)}],
                  "6n6e": [{1, 70, 10601, 1139, 56, 2015}, {(1139, 10601), (70, 10601), (1139, 2015), (1, 56), (56, 2015), (1, 70)}],
                  "6n8e": [{1, 3, 4, 5, 74, 56}, {(4, 74), (3, 4), (5, 56), (1, 5), (1, 56), (56, 74), (1, 4), (1, 3)}]}
    ,
             "snap-com-youtube.txt":
                 {"3n3e": [{1, 2, 4}, {(2, 4), (1, 2), (1, 4)}],
                  "5n4e": [{9312, 1, 514, 2, 3}, {(3, 9312), (1, 2), (1, 3), (2, 514)}],
                  "5n6e": [{1, 2, 514, 4, 2059}, {(2, 4), (1, 2), (1, 4), (2, 514), (514, 2059), (2, 2059)}],
                  "5n7e": [{1, 514, 2, 4, 2059}, {(2, 4), (1, 2), (4, 514), (1, 4), (2, 514), (514, 2059), (2, 2059)}],
                  "6n6e": [{1, 1490, 8084, 22, 376, 86015}, {(376, 86015), (1490, 8084), (1490, 86015), (1, 376), (22, 8084), (1, 22)}],
                  "6n8e": [{1, 514, 2, 4, 2059, 376}, {(2, 4), (1, 2), (376, 514), (1, 4), (2, 514), (514, 2059), (1, 376), (2, 2059)}]}
    ,
             "snap-cit-Patents.txt":
                 {"5n7e": [{5073985, 5331683, 3557384, 4485491, 3891996},
                           {(3891996, 5073985), (4485491, 5331683), (3557384, 5073985), (3557384, 3891996), (3557384, 5331683), (4485491, 5073985), (3557384, 4485491)}],
                  "6n8e": [{5362304, 5157792, 5495620, 4936805, 3398406, 4820221},
                           {(3398406, 4820221), (4820221, 5362304), (5157792, 5495620), (3398406, 5157792), (4820221, 4936805), (3398406, 5495620), (5157792, 5362304), (3398406, 4936805)}]}}


def load_graph(file_path):
    nodes_set, edges_set = set(), set()
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if not line.startswith('#'):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        u, v = int(parts[0]), int(parts[1])
                        nodes_set.add(u)
                        nodes_set.add(v)
                        edges_set.add(tuple(sorted((u, v))))
                    except ValueError:
                        print(f"Skipping malformed line: {line.strip()}")
    return nodes_set, edges_set


def adjacency_list(nodes, edges):
    adj_list = collections.defaultdict(set)
    for u, v in edges:
        adj_list[u].add(v)
        adj_list[v].add(u)
    for node in nodes:
        if node not in adj_list:
            adj_list[node] = set()
    return adj_list


def sample_graph(adj_list, num_sample, protected_nodes, protected_edges):
    mandatory_nodes = protected_nodes.copy()
    for u, v in protected_edges:
        mandatory_nodes.add(u)
        mandatory_nodes.add(v)
    sampled_nodes = mandatory_nodes.copy()
    num_sample -= len(sampled_nodes)
    if num_sample > 0:
        available_sample = list(set(adj_list.keys()) - mandatory_nodes)
        if num_sample > 0:
            chosen = random.sample(available_sample, num_sample)
            sampled_nodes.update(chosen)
    sampled_edges = protected_edges.copy()
    for node in sampled_nodes:
        for neighbor in adj_list.get(node, set()):
            if neighbor in sampled_nodes and node < neighbor:
                sampled_edges.add(tuple(sorted((node, neighbor))))
    return sampled_nodes, sampled_edges


def mapping_function_psi(update_time, num_edges):
    from_nodes_set = set()
    to_nodes_set = set()
    factor_1 = int(update_time[10:14]) + int(update_time[12:16])
    factor_2 = int(update_time[12:16]) + int(update_time[14:18])
    factor_3 = int(update_time[14:18]) + int(update_time[16:20])
    factor_4 = int(update_time[16:20]) + int(update_time[10:14])
    for i in range(num_edges):
        from_node = -((1 + factor_1) * (2 + factor_2) + (3 + factor_3) * (4 + factor_4) + 1234 * i + 1234)
        to_node = -((4 + factor_1) * (3 + factor_2) + (2 + factor_3) * (1 + factor_4) + 4321 * i + 4321)
        from_nodes_set.add(from_node)
        to_nodes_set.add(to_node)
    s_nodes_set = from_nodes_set | to_nodes_set
    s_edges_set = set()
    from_nodes_list, to_nodes_list = sorted(list(from_nodes_set)), sorted(list(to_nodes_set))
    count, from_idx, to_idx = 0, 0, 0
    while count < num_edges:
        from_node = from_nodes_list[from_idx]
        to_node = to_nodes_list[to_idx]
        edge_to_add = tuple(sorted((from_node, to_node)))
        if edge_to_add not in s_edges_set:
            s_edges_set.add(edge_to_add)
            count += 1
        from_idx = (from_idx + 1) % len(from_nodes_list)
        to_idx = (to_idx + 2) % len(to_nodes_list)
        if len(s_edges_set) >= len(from_nodes_list) * len(to_nodes_list):
            break
    return s_nodes_set, s_edges_set


def generate_update(g_nodes_set, g_edges_set, num_update_edges, update_type, protected_nodes=None, protected_edges=None):
    update_time = datetime.now().strftime("%Y%m%d%H%M%S%f")
    if update_type == "Addition":
        nodes_to_append, edges_to_append = set(), set()
        max_node = max(g_nodes_set)
        existing_nodes = list(g_nodes_set)
        new_node = max_node + 1
        for _ in range(num_update_edges):
            nodes_to_append.add(new_node)
            existing_node = random.choice(existing_nodes)
            edges_to_append.add(tuple(sorted((new_node, existing_node))))
            new_node += 1
        return nodes_to_append, edges_to_append, update_time
    elif update_type == "Deletion":
        deletable_edges = {edge for edge in g_edges_set if edge[0] not in protected_nodes and edge[1] not in protected_nodes and edge not in protected_edges}
        max_attempts = 500
        for _ in range(max_attempts):
            edges_to_remove = set(random.sample(list(deletable_edges), k=num_update_edges))
            available_edges = g_edges_set - edges_to_remove
            adj = defaultdict(int)
            for u, v in available_edges:
                adj[u] += 1
                adj[v] += 1
            candidate_nodes = {node for edge in edges_to_remove for node in edge}
            nodes_to_remove = {node for node in candidate_nodes if adj[node] == 0}
            if nodes_to_remove:
                return nodes_to_remove, edges_to_remove, update_time


def generate_subgraph(g_nodes_set, g_edges_set, num_subgraph_edges):
    canonical_edges = {tuple(sorted(e)): e for e in g_edges_set}
    norm_edges = set(canonical_edges.keys())
    adj_list = collections.defaultdict(set)
    for u, v in norm_edges:
        adj_list[u].add(v)
        adj_list[v].add(u)
    node_degrees = {node: len(adj_list[node]) for node in g_nodes_set}
    start_node_queue = [(-degree, random.random(), node) for node, degree in node_degrees.items() if degree > 0]
    heapq.heapify(start_node_queue)
    max_attempts = min(100, len(start_node_queue))
    for _ in range(max_attempts):
        _, _, start_node = heapq.heappop(start_node_queue)
        subgraph_nodes = {start_node}
        norm_subgraph_edges = set()
        edge_queue = []
        for neighbor in adj_list[start_node]:
            edge = tuple(sorted((start_node, neighbor)))
            priority = (-1, random.random())
            heapq.heappush(edge_queue, (priority, edge))
        while edge_queue and len(norm_subgraph_edges) < num_subgraph_edges:
            _, (node1, node2) = heapq.heappop(edge_queue)
            edge = (node1, node2)
            if edge in norm_subgraph_edges:
                continue
            norm_subgraph_edges.add(edge)
            newly_added_nodes = set()
            if node1 not in subgraph_nodes:
                subgraph_nodes.add(node1)
                newly_added_nodes.add(node1)
            if node2 not in subgraph_nodes:
                subgraph_nodes.add(node2)
                newly_added_nodes.add(node2)
            for new_node in newly_added_nodes:
                for neighbor in adj_list[new_node]:
                    if neighbor in subgraph_nodes:
                        continue
                    new_edge = tuple(sorted((new_node, neighbor)))
                    if new_edge not in norm_subgraph_edges:
                        priority = (-1, random.random())
                        heapq.heappush(edge_queue, (priority, new_edge))
            if not edge_queue and len(norm_subgraph_edges) < num_subgraph_edges:
                for node in subgraph_nodes:
                    for neighbor in adj_list[node]:
                        if neighbor in subgraph_nodes:
                            continue
                        new_edge = tuple(sorted((node, neighbor)))
                        if new_edge not in norm_subgraph_edges:
                            priority = (0, random.random())
                            heapq.heappush(edge_queue, (priority, new_edge))
        if len(norm_subgraph_edges) >= num_subgraph_edges:
            subgraph_edges = {canonical_edges[norm_e] for norm_e in norm_subgraph_edges}
            return subgraph_nodes, subgraph_edges
    if 'norm_subgraph_edges' in locals() and norm_subgraph_edges:
        subgraph_edges = {canonical_edges[norm_e] for norm_e in norm_subgraph_edges}
        return subgraph_nodes, subgraph_edges
    if len(g_edges_set) >= num_subgraph_edges:
        sampled_edges = set(random.sample(list(g_edges_set), num_subgraph_edges))
        sampled_nodes = {node for edge in sampled_edges for node in edge}
        return sampled_nodes, sampled_edges
    return set(), set()


def build_graph(file_path):
    graph = collections.defaultdict(set)
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                try:
                    nodes = line.strip().split()
                    if len(nodes) == 2:
                        u, v = map(int, nodes)
                        graph[u].add(v)
                        graph[v].add(u)
                except (ValueError, IndexError):
                    print(f"Skipping malformed line in {file_path}")
                    continue
    except FileNotFoundError:
        print("file not found")
        return graph
    return graph


def find_3n3e_subgraph(graph):
    #      a
    #     / \
    #    /   \
    #   b-----c
    for a in graph:
        for b in graph[a]:
            if a >= b:
                continue
            common_neighbors = graph[a] & graph[b]
            if common_neighbors:
                c = common_neighbors.pop()
                nodes_set = {a, b, c}
                edge_set = {tuple(sorted((a, b))),
                            tuple(sorted((b, c))),
                            tuple(sorted((a, c)))}
                return nodes_set, edge_set
    return None, None


def find_5n4e_subgraph(graph):
    #       a
    #      / \
    #     b   c
    #    /     \
    #   d       e
    for a in graph:
        if len(graph[a]) < 2:
            continue
        for b, c in itertools.combinations(graph[a], 2):
            for d in graph[b]:
                if d == a:
                    continue
                for e in graph[c]:
                    if e == a:
                        continue
                    nodes_set = {a, b, c, d, e}
                    if len(nodes_set) == 5:
                        edges_set = {tuple(sorted((a, b))), tuple(sorted((a, c))),
                                     tuple(sorted((b, d))), tuple(sorted((c, e)))}
                        return nodes_set, edges_set
    return None, None


def find_5n6e_subgraph(graph):
    #   a-----b
    #    \   /
    #     \ /
    #      c
    #     / \
    #    /   \
    #   d-----e
    for c in sorted(graph.keys()):
        neighbors = list(graph[c])
        wings = []
        for u, v in combinations(neighbors, 2):
            if v in graph[u]:
                wings.append({u, v})
        for i in range(len(wings)):
            for j in range(i + 1, len(wings)):
                wing1 = wings[i]
                wing2 = wings[j]
                if wing1.isdisjoint(wing2):
                    a, b = tuple(wing1)
                    d, e = tuple(wing2)
                    nodes_set = {c, a, b, d, e}
                    edges_set = {tuple(sorted((c, a))), tuple(sorted((c, b))), tuple(sorted((a, b))),
                                 tuple(sorted((c, d))), tuple(sorted((c, e))), tuple(sorted((d, e)))}
                    return nodes_set, edges_set
    return None, None


def find_5n7e_subgraph(graph):
    #         a
    #        / \
    #       /   \
    #      b-----c
    #     / \   /
    #    /   \ /
    #   d-----e
    for b in graph:
        if len(graph[b]) < 3:
            continue
        for c, e in combinations(graph[b], 2):
            if c not in graph[e]:
                continue
            a_candidates = (graph[b] & graph[c]) - {e}
            if not a_candidates:
                continue
            d_candidates = (graph[b] & graph[e]) - {c}
            for a in a_candidates:
                for d in d_candidates:
                    if a == d:
                        continue
                    nodes_set = {a, b, c, d, e}
                    if len(nodes_set) < 5:
                        continue
                    edges_set = {tuple(sorted((a, b))), tuple(sorted((a, c))), tuple(sorted((b, c))),
                                 tuple(sorted((b, d))), tuple(sorted((b, e))), tuple(sorted((c, e))), tuple(sorted((d, e)))}
                    return nodes_set, edges_set
    return None, None


def find_6n6e_subgraph(graph):
    #         a
    #        / \
    #       /   \
    #      b     c
    #     /       \
    #    /         \
    #   d-----f-----e
    for start_node in sorted(graph.keys()):
        stack = [(start_node, [start_node])]
        while stack:
            current_node, path = stack.pop()
            if len(path) == 6:
                if start_node in graph[current_node]:
                    nodes_set = set(path)
                    edges_set = set()
                    for i in range(len(path) - 1):
                        edges_set.add(tuple(sorted((path[i], path[i + 1]))))
                    edges_set.add(tuple(sorted((path[-1], start_node))))
                    return nodes_set, edges_set
                continue
            for neighbor in graph[current_node]:
                if neighbor not in path:
                    new_path = path + [neighbor]
                    stack.append((neighbor, new_path))
    return None, None


def find_6n8e_subgraph(graph):
    #         a
    #        / \
    #       /   \
    #      b     c
    #     / \   / \
    #    /   \ /   \
    #   d-----f-----e
    for f in graph:
        f_neighbors = list(graph[f])
        if len(f_neighbors) < 4:
            continue
        for b, c in combinations(f_neighbors, 2):
            a_candidates = (graph[b] & graph[c]) - {f}
            if not a_candidates:
                continue
            d_candidates = (graph[f] & graph[b]) - {c}
            if not d_candidates:
                continue
            e_candidates = (graph[f] & graph[c]) - {b}
            if not e_candidates:
                continue
            a = list(a_candidates)[0]
            for d in d_candidates:
                if d == a: continue
                for e in e_candidates:
                    if e == a or e == d: continue
                    node_set = {a, b, c, d, e, f}
                    edge_set = {tuple(sorted((a, b))), tuple(sorted((b, d))), tuple(sorted((d, f))),
                                tuple(sorted((f, e))), tuple(sorted((e, c))), tuple(sorted((c, a))),
                                tuple(sorted((f, b))), tuple(sorted((f, c)))}
                    return node_set, edge_set
    return None, None
