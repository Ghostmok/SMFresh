import gc
import math
import random
import secrets
import sys
import time
from Cryptosystem_DLHS import p, g, sk, pk, e_to_scalar
from Cryptosystem_RSA import N, E, D, CuckooFilter, Reinsertion
from datetime import datetime
from functools import reduce
from gmpy2 import powmod
from Graph_Operation import (path_prefix, filename, subgraphs,
                             load_graph, adjacency_list, sample_graph, mapping_function_psi, generate_update, generate_subgraph)
from Incremental_MerkleTree import Incremental_MerkleTree
from math import gcd
from MerkleTree import MerkleTree
from Overhead_Monitor import *
from sympy import mod_inverse
from tqdm import tqdm


current_time = datetime.now().strftime("%Y%m%d%H%M%S%f")

count_dict = {("Addition", "Yes"): 0, ("Addition", "No"): 0,
              ("Deletion", "Yes"): 0, ("Deletion", "No"): 0}


def Triple_Verification():
    # --------------------------------
    GDB_INDEX = 0             # 0[em]: 36692 Nodes & 367662 Edges; 1[yt]: 1134890 Nodes & 2987624 Edges; 2[pt]: 3774768 Nodes & 16518948 Edges
    SUB_INDEX = "3n3e"        # 3n3e / 5n4e / 5n6e / 5n7e / 6n6e / 6n8e
    # sample_size = 80 * 1000   # 20k / 40k/ 80k/ 160k / 320k / 640k / 1.28M / 2.56M
    # --------------------------------
    num_s_edges = 20
    num_update_edges = 50
    # num_subgraph_edges = 100
    # --------------------------------
    # total_updates = 100000
    # batch_sizes = [100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000]
    # current_batch = batch_sizes[9]
    # num_update_edges = current_batch
    # commit_interval = total_updates // current_batch
    # --------------------------------
    load_factor = 0.75
    interval = 10
    # --------------------------------
    current_iteration = 0
    max_iteration = 31         # Or longer, 67 rounds
    # --------------------------------
    update_nodes_sigs, update_edges_sigs = [], []
    unioned_nodes_sigs, unioned_edges_sigs = [], []
    n_addition_buf, e_addition_buf = [], []
    n_deletion_buf, e_deletion_buf = [], []
    # --------------------------------
    while current_iteration < max_iteration:
    # while current_iteration < commit_interval + 1:
        if current_iteration == 0:
            print("\n=================== 🥳INITIATING GRAPH DATA OUTSOURCING AND QUERY VERIFICATION🥳 ===================")
            DO_Init_TO, RP_Init_TO, CS_Init_TO = 0, 0, 0

            # TODO The DO and RP generate a time-associated graph structure S=(s_nodes_set, s_edges_set) through a mapping function ψ
            Mapping_TO = time.perf_counter()
            s_nodes_set, s_edges_set = mapping_function_psi(current_time, num_s_edges)
            Mapping_TO = time.perf_counter() - Mapping_TO
            DO_Init_TO += Mapping_TO
            RP_Init_TO += Mapping_TO
            Record(Operation="Mapping", Time_Overhead=Mapping_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The DO inserts the temporal structure S into the initial graph database G=(g_nodes_set, g_edges_set)
            g_nodes_set, g_edges_set = load_graph(path_prefix + filename[GDB_INDEX])
            # adj_list = adjacency_list(g_nodes_set, g_edges_set)
            # g_nodes_set, g_edges_set = sample_graph(adj_list, sample_size,
            #                                         subgraphs[filename[GDB_INDEX]][SUB_INDEX][0], subgraphs[filename[GDB_INDEX]][SUB_INDEX][1])
            DO_Insert_S2G_TO = time.perf_counter()
            g_nodes_set |= s_nodes_set
            g_edges_set |= s_edges_set
            DO_Insert_S2G_TO = time.perf_counter() - DO_Insert_S2G_TO
            DO_Init_TO += DO_Insert_S2G_TO
            Record(Operation="DO_Insert_S2G", Time_Overhead=DO_Insert_S2G_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The DO transforms the initial graph database G, which embeds the temporal structure S, into a Merkle tree and computes the root hash
            DO_TreeOp_TO = time.perf_counter()
            g_nodes_MHT = MerkleTree(list(g_nodes_set))
            g_edges_MHT = MerkleTree(list(g_edges_set))
            g_nodes_root = int(g_nodes_MHT.root_hash, 16)
            g_edges_root = int(g_edges_MHT.root_hash, 16)
            DO_TreeOp_TO = time.perf_counter() - DO_TreeOp_TO
            DO_Init_TO += DO_TreeOp_TO
            Record(Operation="DO_TreeOp", Time_Overhead=DO_TreeOp_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The DO signs the root hash and sends it along with the data graph to the CS.
            DO_SignRoot_TO = time.perf_counter()
            g_nodes_sig = pow(g, (sk * g_nodes_root) % (p - 1), p)
            g_edges_sig = pow(g, (sk * g_edges_root) % (p - 1), p)
            DO_SignRoot_TO = time.perf_counter() - DO_SignRoot_TO
            DO_Init_TO += DO_SignRoot_TO
            Record(Operation="DO_SignRoot", Time_Overhead=DO_SignRoot_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO Simulate a subgraph matching scenario to generate the ground-truth query result rq=(rq_nodes_set, rq_edges_set)
            q_nodes_set, q_edges_set = subgraphs[filename[GDB_INDEX]][SUB_INDEX]                              # Index-based
            # q_nodes_set, q_edges_set = generate_subgraph(g_nodes_set, g_edges_set, num_subgraph_edges)      # Based on heuristic greedy algorithm
            rq_nodes_set, rq_edges_set = q_nodes_set.copy(), q_edges_set.copy()

            # ————————————————————————————————— ✅️INTEGRITY VERIFICATION SUCCESSFUL✅ —————————————————————————————————
            # TODO The CS initializes IMMHTs for both the node and edge sets based on the initial graph database received from the DO
            CS_TreeOp_TO = time.perf_counter()
            node_IMMHT = Incremental_MerkleTree(list(g_nodes_set))
            edge_IMMHT = Incremental_MerkleTree(list(g_edges_set))
            CS_TreeOp_TO = time.perf_counter() - CS_TreeOp_TO
            CS_Init_TO += CS_TreeOp_TO
            Record(Operation="CS_TreeOp", Time_Overhead=CS_TreeOp_TO, Update_Type=None, Query_or_Not="Yes")

            CS_GenProof_TO, RP_VerifyProof_TO = 0, 0
            dedup, proofs = set(), []
            for rq_set, IMMHT, g_sig in [(rq_nodes_set, node_IMMHT, g_nodes_sig),
                                         (rq_edges_set, edge_IMMHT, g_edges_sig)]:
                for e in rq_set:
                    # TODO The CS generates IMMHT membership proofs for the elements in the query result
                    GenProof_Start_Time = time.perf_counter()
                    proof = IMMHT.get_proof(e)
                    CS_GenProof_TO += time.perf_counter() - GenProof_Start_Time

                    # TODO The RP recalculates the IMMHT root hash based on the proofs and verifies whether it matches the root hash declared by the CS
                    VerifyProof_Start_Time = time.perf_counter()
                    recomputed_root = Incremental_MerkleTree.immht_recompute(proof)
                    if recomputed_root != proof["Root_Hash"]:
                        sys.exit()
                    RP_VerifyProof_TO += time.perf_counter() - VerifyProof_Start_Time
                    dedup.add(recomputed_root)
                    proofs.append(proof)
            # TODO After recalculation, the RP verifies whether the node set and edge set each generate a unified and consistent IMMHT root hash
            if len(dedup) != 2:
                sys.exit()
            VerifyProof_Start_Time = time.perf_counter()

            # TODO RP verifies the homomorphic signatures to reverse-engineer and confirm whether the graph data held by the CS is consistent with that uploaded by the DO
            Dedup = {pow(pk, int(hex_str, 16), p) for hex_str in dedup}
            if Dedup != {g_nodes_sig, g_edges_sig}:
                print(f"😭Error: Integrity verification of the outsourcing phase failed")
                sys.exit()
            RP_VerifyProof_TO += time.perf_counter() - VerifyProof_Start_Time
            CS_Init_TO += CS_GenProof_TO
            Record(Operation="CS_GenProof", Time_Overhead=CS_GenProof_TO, Update_Type=None, Query_or_Not="Yes")
            RP_Init_TO += RP_VerifyProof_TO
            Record(Operation="RP_VerifyProof", Time_Overhead=RP_VerifyProof_TO, Update_Type=None, Query_or_Not="Yes")

            # print("\n============================ ❌INTEGRITY VERIFICATION FAILURE EXAMPLE❌ ============================")
            # chosen_node = random.choice(list(rq_nodes_set))
            # r9_nodes_set = {-e if e == chosen_node else e for e in rq_nodes_set}
            # chosen_edge = random.choice(list(rq_edges_set))
            # r9_edges_set = {(-x if (x, y) == chosen_edge else x, -y if (x, y) == chosen_edge else y) for (x, y) in rq_edges_set}
            # for r9_set, IMMHT, g_sig in [(r9_nodes_set, node_IMMHT, g_nodes_sig),
            #                              (r9_edges_set, edge_IMMHT, g_edges_sig)]:
            #     for e in r9_set:
            #         proof = IMMHT.get_proof(e)
            #         recomputed_root = Incremental_MerkleTree.immht_recompute(proof)
            #         if pow(pk, int(recomputed_root, 16), p) != g_sig:
            #             print(f"😋Cause: \033[31m{chosen_node if r9_set == r9_nodes_set else chosen_edge}\033[0m was artificially \033[31mnegated\033[0m")

            # ————————————————————————————————— ✅️FRESHNESS VERIFICATION SUCCESSFUL✅ —————————————————————————————————
            # TODO The RP merges the locally generated structure S with the received query result Rq to form the augmented result for subsequent verification
            RP_Insert_S2R_TO = time.perf_counter()
            rq_nodes_set |= s_nodes_set
            rq_edges_set |= s_edges_set
            RP_Insert_S2R_TO = time.perf_counter() - RP_Insert_S2R_TO
            RP_Init_TO += RP_Insert_S2R_TO
            Record(Operation="RP_Insert_S2R", Time_Overhead=RP_Insert_S2R_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The CS encrypts the scalar representations of all elements in the data graph with its RSA private key
            CS_EncG_TO = time.perf_counter()
            print()
            enc_g_nodes = {powmod(e_to_scalar(node), D, N) for node in tqdm(g_nodes_set, f"🫠Encrypting in progress...", unit=" elements")}
            enc_g_edges = {powmod(e_to_scalar(edge), D, N) for edge in tqdm(g_edges_set, f"🫠Encrypting in progress...", unit=" elements")}
            CS_EncG_TO = time.perf_counter() - CS_EncG_TO
            CS_Init_TO += CS_EncG_TO
            Record(Operation="CS_EncG", Time_Overhead=CS_EncG_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The CS inserts all encrypted elements into a newly initialized cuckoo filter and sends it to the RP
            CS_CF_TO = time.perf_counter()
            cf = CuckooFilter(capacity=int(len(enc_g_nodes | enc_g_edges) / load_factor / 4))
            for enc_data in enc_g_nodes | enc_g_edges:
                cf.insert(enc_data)
            CS_CF_TO = time.perf_counter() - CS_CF_TO
            CS_Init_TO += CS_CF_TO
            Record(Operation="CS_CF", Time_Overhead=CS_CF_TO, Update_Type=None, Query_or_Not="Yes")
            Reinsertion(cf, enc_g_nodes | enc_g_edges, True)

            # TODO The RP applies random blinding factors to the augmented result set and sends the blinded data to the CS
            RP_BlndRq_TO = time.perf_counter()
            rq_nodes_inv, rq_edges_inv = [], []
            blnd_rq_nodes, blnd_rq_edges = [], []
            for rq_set, blnd_rq_list, rq_inv_list in [(rq_nodes_set, blnd_rq_nodes, rq_nodes_inv),
                                                      (rq_edges_set, blnd_rq_edges, rq_edges_inv)]:
                for e in rq_set:
                    while True:
                        r = secrets.randbelow(N - 2) + 2
                        if gcd(r, N) == 1:
                            break
                    r_inv = mod_inverse(r, N)
                    blnd_e = (e_to_scalar(e) * pow(r, E, N)) % N
                    blnd_rq_list.append(blnd_e)
                    rq_inv_list.append(r_inv)
            RP_BlndRq_TO = time.perf_counter() - RP_BlndRq_TO
            RP_Init_TO += RP_BlndRq_TO
            Record(Operation="RP_BlndRq", Time_Overhead=RP_BlndRq_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The CS encrypts the blinded challenge set from the RP with its RSA private key and sends the response set back
            CS_EncRq_TO = time.perf_counter()
            enc_blnd_rq_nodes = [pow(blnd_node, D, N) for blnd_node in blnd_rq_nodes]
            enc_blnd_rq_edges = [pow(blnd_edge, D, N) for blnd_edge in blnd_rq_edges]
            CS_EncRq_TO = time.perf_counter() - CS_EncRq_TO
            CS_Init_TO += CS_EncRq_TO
            Record(Operation="CS_EncRq", Time_Overhead=CS_EncRq_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The RP unblinds the response set to recover the encrypted representations of its elements and checks them against the cuckoo filter to verify the freshness
            RP_SeekCF_TO = time.perf_counter()
            enc_rq_nodes, enc_rq_edges = set(), set()
            for enc_blnd_rq_list, rq_inv_list, enc_rq_set in [(enc_blnd_rq_nodes, rq_nodes_inv, enc_rq_nodes),
                                                              (enc_blnd_rq_edges, rq_edges_inv, enc_rq_edges)]:
                for enc_blnd_rq, rq_inv in zip(enc_blnd_rq_list, rq_inv_list):
                    e = (enc_blnd_rq * rq_inv) % N
                    enc_rq_set.add(e)
                    if not cf.seek(e):
                        print("😭Error: False negative phenomenon occurs")
                        sys.exit()
            RP_SeekCF_TO = time.perf_counter() - RP_SeekCF_TO

            # print("============================ ❌FRESHNESS VERIFICATION FAILURE EXAMPLE❌ ============================")
            # enc_9_nodes = enc_g_nodes - {powmod(e_to_scalar(node), D, N) for node in s_nodes_set}
            # enc_9_edges = enc_g_edges - {powmod(e_to_scalar(edge), D, N) for edge in s_edges_set}
            # df = CuckooFilter(capacity=int(len(enc_9_nodes | enc_9_edges) / load_factor / 4))
            # for enc_data in enc_9_nodes | enc_9_edges:
            #     df.insert(enc_data)
            # Reinsertion(df, enc_9_nodes | enc_9_edges, False)
            # n_count, e_count = 0, 0
            # for e in enc_rq_nodes:
            #     if not df.seek(e):
            #         n_count += 1
            # print(f"😭\033[31m{n_count}\033[0m nodes were not found in the Cuckoofilter, 😋caused by the incorrect version selection, and the length of s_nodes_set being \033[31m{len(s_nodes_set)}\033[0m")
            # for e in enc_rq_edges:
            #     if not df.seek(e):
            #         e_count += 1
            # print(f"😭\033[31m{e_count}\033[0m edges were not found in the Cuckoofilter, 😋caused by the incorrect version selection, and the length of s_edges_set being \033[31m{len(s_edges_set)}\033[0m\n")

            # ———————————————————————————————— ✅️CORRECTNESS VERIFICATION SUCCESSFUL✅ ————————————————————————————————
            # TODO The RP removes the encrypted representations of the augmented result set from the cuckoo filter to simulate the difference set G−Rq
            RP_Dif_TO = time.perf_counter()
            cf.delete(enc_rq_nodes | enc_rq_edges)
            RP_Dif_TO = time.perf_counter() - RP_Dif_TO
            RP_Init_TO += RP_Dif_TO
            Record(Operation="RP_Dif", Time_Overhead=RP_Dif_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The RP applies random blinding factors to blind the query graph and sends the result to the CS
            RP_BlndQ_TO = time.perf_counter()
            q_nodes_inv, q_edges_inv = [], []
            blnd_q_nodes, blnd_q_edges = [], []
            for q_set, blnd_q_list, q_inv_list in [(q_nodes_set, blnd_q_nodes, q_nodes_inv),
                                                   (q_edges_set, blnd_q_edges, q_edges_inv)]:
                for e in q_set:
                    while True:
                        r = secrets.randbelow(N - 2) + 2
                        if gcd(r, N) == 1:
                            break
                    r_inv = mod_inverse(r, N)
                    blnd_e = (e_to_scalar(e) * pow(r, E, N)) % N
                    blnd_q_list.append(blnd_e)
                    q_inv_list.append(r_inv)
            RP_BlndQ_TO = time.perf_counter() - RP_BlndQ_TO
            RP_Init_TO += RP_BlndQ_TO
            Record(Operation="RP_BlndQ", Time_Overhead=RP_BlndQ_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO The CS encrypts the blinded challenge set from the RP with its RSA private key and sends the response set back
            CS_EncQ_TO = time.perf_counter()
            enc_blnd_q_nodes = [pow(blnd_q_node, D, N) for blnd_q_node in blnd_q_nodes]
            enc_blnd_q_edges = [pow(blnd_q_edge, D, N) for blnd_q_edge in blnd_q_edges]
            CS_EncQ_TO = time.perf_counter() - CS_EncQ_TO
            CS_Init_TO += CS_EncQ_TO
            Record(Operation="CS_EncQ", Time_Overhead=CS_EncQ_TO, Update_Type=None, Query_or_Not="Yes")

            # TODO 🦜🐦🦜🐦🦜🐦🦜🐦🦜🐦
            num_queries = len(enc_blnd_q_nodes) + len(enc_blnd_q_edges)
            FP_Rate = (2 * cf.bucket_size) / (2**cf.fp_size)
            FP_Threshold = math.ceil(num_queries * FP_Rate * 2)

            # TODO The RP unblinds the response set and looks them up in the cuckoo filter to verify the correctness of the matching result
            _RP_SeekCF_TO = time.perf_counter()
            enc_q_nodes, enc_q_edges = set(), set()
            FP_Count = 0
            for enc_blnd_q_list, q_inv_list, enc_q_set in [(enc_blnd_q_nodes, q_nodes_inv, enc_q_nodes),
                                                           (enc_blnd_q_edges, q_edges_inv, enc_q_edges)]:
                for enc_blnd_q, q_inv in zip(enc_blnd_q_list, q_inv_list):
                    e = (enc_blnd_q * q_inv) % N
                    enc_q_set.add(e)
                    if cf.seek(e):
                        print("🤔False positive phenomenon occurs")
                        FP_Count += 1
            _RP_SeekCF_TO = time.perf_counter() - _RP_SeekCF_TO
            RP_SeekCF_TO += _RP_SeekCF_TO
            RP_Init_TO += RP_SeekCF_TO
            if FP_Count > FP_Threshold:
                print("😭Error: The number of observed false positives significantly exceeds the theoretical rate")
                # sys.exit()
            # --------------------------------
            Record(Operation="RP_SeekCF", Time_Overhead=RP_SeekCF_TO, Update_Type=None, Query_or_Not="Yes")
            Record(Operation="DO_Init", Time_Overhead=DO_Init_TO, Update_Type=None, Query_or_Not="Yes")
            Record(Operation="RP_Init", Time_Overhead=RP_Init_TO, Update_Type=None, Query_or_Not="Yes")
            Record(Operation="CS_Init", Time_Overhead=CS_Init_TO, Update_Type=None, Query_or_Not="Yes")

            # print("=========================== ❌CORRECTNESS VERIFICATION FAILURE EXAMPLE❌ ===========================")
            # r9_nodes_set, r9_edges_set = rq_nodes_set.copy(), rq_edges_set.copy()
            # altered_nodes_num = random.randint(1, len(r9_nodes_set - s_nodes_set))
            # altered_edges_num = random.randint(1, len(r9_edges_set - s_edges_set))
            # for r9_set, s_set, g_set, altered_num in [(r9_nodes_set, s_nodes_set, g_nodes_set, altered_nodes_num),
            #                                           (r9_edges_set, s_edges_set, g_edges_set, altered_edges_num)]:
            #     e_to_remove = random.sample(list(r9_set - s_set), altered_num)
            #     e_to_add = random.sample(list(g_set - r9_set), altered_num)
            #     for e in e_to_remove:
            #         r9_set.remove(e)
            #     for e in e_to_add:
            #         r9_set.add(e)
            # r9_nodes_inv, r9_edges_inv = [], []
            # blnd_r9_nodes, blnd_r9_edges = [], []
            # for r9_set, blnd_r9_list, r9_inv_list in [(r9_nodes_set, blnd_r9_nodes, r9_nodes_inv),
            #                                           (r9_edges_set, blnd_r9_edges, r9_edges_inv)]:
            #     for e in r9_set:
            #         while True:
            #             r = secrets.randbelow(N - 2) + 2
            #             if gcd(r, N) == 1:
            #                 break
            #         r_inv = mod_inverse(r, N)
            #         blnd_e = (e_to_scalar(e) * pow(r, E, N)) % N
            #         blnd_r9_list.append(blnd_e)
            #         r9_inv_list.append(r_inv)
            # enc_blnd_r9_nodes = [pow(blnd_r9_node, D, N) for blnd_r9_node in blnd_r9_nodes]
            # enc_blnd_r9_edges = [pow(blnd_r9_edge, D, N) for blnd_r9_edge in blnd_r9_edges]
            # enc_r9_nodes, enc_r9_edges = set(), set()
            # for enc_blnd_r9_node, r_inv in zip(enc_blnd_r9_nodes, r9_nodes_inv):
            #     enc_r9_node = (enc_blnd_r9_node * r_inv) % N
            #     enc_r9_nodes.add(enc_r9_node)
            # for enc_blnd_r9_edge, r_inv in zip(enc_blnd_r9_edges, r9_edges_inv):
            #     enc_r9_edge = (enc_blnd_r9_edge * r_inv) % N
            #     enc_r9_edges.add(enc_r9_edge)
            # ef = CuckooFilter(capacity=int(len(enc_g_nodes | enc_g_edges) / load_factor / 4))
            # for enc_data in enc_g_nodes | enc_g_edges:
            #     ef.insert(enc_data)
            # Reinsertion(ef, enc_g_nodes | enc_g_edges, False)
            # ef.delete(enc_r9_nodes | enc_r9_edges)
            # n_count, e_count = 0, 0
            # for e in enc_q_nodes:
            #     if ef.seek(e):
            #         n_count += 1
            # print(f"😭\033[31m{n_count}\033[0m nodes were found in the Cuckoofilter, 😋caused by \033[31m{altered_nodes_num}\033[0m nodes being deliberately altered in rq")
            # for e in enc_q_edges:
            #     if ef.seek(e):
            #         e_count += 1
            # print(f"😭\033[31m{e_count}\033[0m edges were found in the Cuckoofilter, 😋caused by \033[31m{altered_edges_num}\033[0m edges being deliberately altered in rq\n")
            # --------------------------------
            cs_overhead = {"Signatures": get_size(g_nodes_sig) + get_size(g_edges_sig),
                           "Proofs": get_size(proofs),
                           "Filter": get_size(cf),
                           "Resp(rq)": get_size(enc_blnd_rq_nodes) + get_size(enc_blnd_rq_edges),
                           "Resp(q)": get_size(enc_blnd_q_nodes) + get_size(enc_blnd_q_edges)}
            rp_overhead = {"blind(rq)": get_size(blnd_rq_nodes) + get_size(blnd_rq_edges),
                           "blind(q)": get_size(blnd_q_nodes) + get_size(blnd_q_edges)}
            print_table(cs_overhead, rp_overhead)
            # --------------------------------
            gc.collect()
            current_iteration = 1
            print()
            print("——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————\n")
        else:
            if current_iteration == 1:
                print("======================== 🥳GRAPH DATA UPDATE AND VERIFICATION IN PROGRESS🥳 ========================\n")
            update_type = "Deletion" if current_iteration % 2 == 0 else "Addition"
            query_or_not = "Yes" if current_iteration % 3 == 1 else "No"
            trigger = (current_iteration % interval == 0) or query_or_not == "Yes"
            # trigger = (current_iteration % commit_interval == 0)
            count_dict[(update_type, query_or_not)] += 1
            print(f"🥳The round {current_iteration} graph update ({update_type}) is currently in progress. RP’s query intention is: {query_or_not}")

            DO_Subseq_TO, RP_Subseq_TO, CS_Subseq_TO = 0, 0, 0

            # TODO The DO initiates a graph update request U=(update_nodes_set, update_edges_set) at the specified update_time.
            update_nodes_set, update_edges_set, update_time = generate_update(g_nodes_set, g_edges_set, num_update_edges, update_type, q_nodes_set, q_edges_set)

            # TODO The DO and RP generate the time-associated graph structure S=(s_nodes_set, s_edges_set)
            DO_Mapping_TO = time.perf_counter()
            s_nodes_set, s_edges_set = mapping_function_psi(update_time, num_s_edges)
            DO_Mapping_TO = time.perf_counter() - DO_Mapping_TO
            DO_Subseq_TO += DO_Mapping_TO
            Record(Operation="DO_Mapping", Time_Overhead=DO_Mapping_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            if query_or_not == "Yes":
                RP_Mapping_TO = DO_Mapping_TO
                RP_Subseq_TO += RP_Mapping_TO
                Record(Operation="RP_Mapping", Time_Overhead=RP_Mapping_TO, Update_Type=update_type, Query_or_Not=query_or_not)

            # TODO The DO inserts the structure S into the graph update U (only when update_type="append") to obtain the newly graph update structure U′=(unioned_nodes_set, unioned_edges_set)
            DO_Insert_S2U_TO = time.perf_counter()
            unioned_nodes_set = update_nodes_set | s_nodes_set if update_type == "Addition" else s_nodes_set
            unioned_edges_set = update_edges_set | s_edges_set if update_type == "Addition" else s_edges_set
            DO_Insert_S2U_TO = time.perf_counter() - DO_Insert_S2U_TO
            DO_Subseq_TO += DO_Insert_S2U_TO
            Record(Operation="DO_Insert_S2U", Time_Overhead=DO_Insert_S2U_TO, Update_Type=update_type, Query_or_Not=query_or_not)

            # TODO After receiving the graph update, the CS generates the updated data graph G'=(updated_nodes_set, updated_edges_set)
            updated_edges_set = (g_edges_set | unioned_edges_set) - update_edges_set if update_type == "Deletion" else (g_edges_set | unioned_edges_set)
            updated_nodes_set = (g_nodes_set | unioned_nodes_set) - update_nodes_set if update_type == "Deletion" else (g_nodes_set | unioned_nodes_set)
            inter_1 = g_nodes_set & update_nodes_set if update_type == "Addition" else set()
            inter_2 = g_edges_set & update_edges_set if update_type == "Addition" else set()
            inter_3, inter_4 = update_nodes_set & s_nodes_set, update_edges_set & s_edges_set
            inter_5, inter_6 = s_nodes_set & g_nodes_set, s_edges_set & g_edges_set
            if any([inter_1, inter_2, inter_3, inter_4, inter_5, inter_6]):
                print(f"🤔Graph Data Conflict")

            # ————————————————————————————————— ✅️INTEGRITY VERIFICATION SUCCESSFUL✅ —————————————————————————————————
            DO_TreeOp_TO = time.perf_counter()
            unioned_nodes_MHT = MerkleTree(list(unioned_nodes_set))
            unioned_nodes_root = int(unioned_nodes_MHT.root_hash, 16)
            unioned_edges_MHT = MerkleTree(list(unioned_edges_set))
            unioned_edges_root = int(unioned_edges_MHT.root_hash, 16)
            DO_TreeOp_TO = time.perf_counter() - DO_TreeOp_TO
            # --------------------------------
            DO_SignRoot_TO = time.perf_counter()
            unioned_nodes_sig = pow(g, (sk * unioned_nodes_root) % (p - 1), p)
            unioned_edges_sig = pow(g, (sk * unioned_edges_root) % (p - 1), p)
            DO_SignRoot_TO = time.perf_counter() - DO_SignRoot_TO
            unioned_nodes_sigs.append(unioned_nodes_sig)
            unioned_edges_sigs.append(unioned_edges_sig)
            # --------------------------------
            CS_TreeOp_TO = time.perf_counter()
            node_IMMHT.addition(list(unioned_nodes_set))
            edge_IMMHT.addition(list(unioned_edges_set))
            CS_TreeOp_TO = time.perf_counter() - CS_TreeOp_TO
            # --------------------------------
            if update_type == "Deletion":
                TreeOp_Start_Time = time.perf_counter()
                update_nodes_MHT = MerkleTree(list(update_nodes_set))
                update_edges_MHT = MerkleTree(list(update_edges_set))
                update_nodes_root = int(update_nodes_MHT.root_hash, 16)
                update_edges_root = int(update_edges_MHT.root_hash, 16)
                DO_TreeOp_TO += time.perf_counter() - TreeOp_Start_Time
                # --------------------------------
                SignRoot_Start_Time = time.perf_counter()
                update_nodes_RHsig = pow(g, (sk * update_nodes_root) % (p - 1), p)
                update_edges_RHsig = pow(g, (sk * update_edges_root) % (p - 1), p)
                DO_SignRoot_TO += time.perf_counter() - SignRoot_Start_Time
                update_nodes_sigs.append(update_nodes_RHsig)
                update_edges_sigs.append(update_edges_RHsig)
                # --------------------------------
                TreeOp_Start_Time = time.perf_counter()
                node_IMMHT.deletion(list(update_nodes_set))
                edge_IMMHT.deletion(list(update_edges_set))
                CS_TreeOp_TO += time.perf_counter() - TreeOp_Start_Time
                # --------------------------------
            DO_Subseq_TO += DO_TreeOp_TO
            Record(Operation="DO_TreeOp", Time_Overhead=DO_TreeOp_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            DO_Subseq_TO += DO_SignRoot_TO
            Record(Operation="DO_SignRoot", Time_Overhead=DO_SignRoot_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            CS_Subseq_TO += CS_TreeOp_TO
            Record(Operation="CS_TreeOp", Time_Overhead=CS_TreeOp_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            # --------------------------------
            if query_or_not == "Yes":
                q_nodes_set, q_edges_set = subgraphs[filename[GDB_INDEX]][SUB_INDEX]                                       # Index-based
                # q_nodes_set, q_edges_set = generate_subgraph(updated_nodes_set, updated_edges_set, num_subgraph_edges)   # Based on heuristic greedy algorithm
                rq_nodes_set, rq_edges_set = q_nodes_set.copy(), q_edges_set.copy()
                # --------------------------------
                RP_GenHomo_TO = time.perf_counter()
                homo_nodes_sig = reduce(lambda acc, x: (acc * x) % p, unioned_nodes_sigs, g_nodes_sig)
                homo_edges_sig = reduce(lambda acc, x: (acc * x) % p, unioned_edges_sigs, g_edges_sig)
                RP_GenHomo_TO = time.perf_counter() - RP_GenHomo_TO
                if update_nodes_sigs or update_edges_sigs:
                    GenRHHomo_Start_Time = time.perf_counter()
                    homo_nodes_sig = reduce(lambda acc, x: (acc * pow(x, -1, p)) % p, update_nodes_sigs, homo_nodes_sig)
                    homo_edges_sig = reduce(lambda acc, x: (acc * pow(x, -1, p)) % p, update_edges_sigs, homo_edges_sig)
                    RP_GenHomo_TO += time.perf_counter() - GenRHHomo_Start_Time
                RP_Subseq_TO += RP_GenHomo_TO
                Record(Operation="RP_GenHomo", Time_Overhead=RP_GenHomo_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                g_nodes_sig, g_edges_sig = homo_nodes_sig, homo_edges_sig
                # --------------------------------
                CS_GenProof_TO, RP_VerifyProof_TO = 0, 0
                dedup = set()
                for rq_set, IMMHT, homo_sig in [(rq_nodes_set, node_IMMHT, homo_nodes_sig),
                                                (rq_edges_set, edge_IMMHT, homo_edges_sig)]:
                    for e in rq_set:
                        GenProof_Start_Time = time.perf_counter()
                        proof = IMMHT.get_proof(e)
                        CS_GenProof_TO += time.perf_counter() - GenProof_Start_Time
                        # --------------------------------
                        VerifyProof_Start_Time = time.perf_counter()
                        recomputed_root = Incremental_MerkleTree.immht_recompute(proof)
                        if not recomputed_root == proof["Root_Hash"]:
                            sys.exit()
                        dedup.add(recomputed_root)
                        RP_VerifyProof_TO += time.perf_counter() - VerifyProof_Start_Time
                if len(dedup) != 2:
                    sys.exit()
                VerifyProof_Start_Time = time.perf_counter()
                # --------------------------------
                Dedup = {pow(pk, int(hex_str, 16), p) for hex_str in dedup}
                if Dedup != {homo_nodes_sig, homo_edges_sig}:
                    print(f"😭Error: Expectation of the root hash, which is computed based on the hash chain, does not align with the homomorphic signature")
                    sys.exit()
                RP_VerifyProof_TO += time.perf_counter() - VerifyProof_Start_Time
                CS_Subseq_TO += CS_GenProof_TO
                Record(Operation="CS_GenProof", Time_Overhead=CS_GenProof_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                RP_Subseq_TO += RP_VerifyProof_TO
                Record(Operation="RP_VerifyProof", Time_Overhead=RP_VerifyProof_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                for cache in [update_nodes_sigs, update_edges_sigs, unioned_nodes_sigs, unioned_edges_sigs, dedup]:
                    cache.clear()

            # ————————————————————————————————— ✅️FRESHNESS VERIFICATION SUCCESSFUL✅ —————————————————————————————————
            CS_EncNew_TO = time.perf_counter()
            enc_unioned_nodes = {powmod(e_to_scalar(node), D, N) for node in unioned_nodes_set}
            enc_unioned_edges = {powmod(e_to_scalar(edge), D, N) for edge in unioned_edges_set}
            n_addition_buf.append(enc_unioned_nodes)
            e_addition_buf.append(enc_unioned_edges)
            if update_type == "Deletion":
                enc_update_nodes = {powmod(e_to_scalar(node), D, N) for node in update_nodes_set}
                enc_update_edges = {powmod(e_to_scalar(edge), D, N) for edge in update_edges_set}
                n_deletion_buf.append(enc_update_nodes)
                e_deletion_buf.append(enc_update_edges)
            CS_EncNew_TO = time.perf_counter() - CS_EncNew_TO
            CS_Subseq_TO += CS_EncNew_TO
            Record(Operation="CS_EncNew", Time_Overhead=CS_EncNew_TO, Update_Type=update_type, Query_or_Not=query_or_not)
            # --------------------------------
            if trigger:
                enc_updated_nodes = enc_g_nodes.copy()
                enc_updated_edges = enc_g_edges.copy()
                CS_UpdateCipher_TO = time.perf_counter()
                if n_addition_buf and e_addition_buf:
                    addition_nodes = set.union(*n_addition_buf)
                    addition_edges = set.union(*e_addition_buf)
                    enc_updated_nodes.update(addition_nodes)
                    enc_updated_edges.update(addition_edges)
                if n_deletion_buf and e_deletion_buf:
                    deletion_nodes = set.union(*n_deletion_buf)
                    deletion_edges = set.union(*e_deletion_buf)
                    enc_updated_nodes.difference_update(deletion_nodes)
                    enc_updated_edges.difference_update(deletion_edges)
                CS_UpdateCipher_TO = time.perf_counter() - CS_UpdateCipher_TO
                CS_Subseq_TO += CS_UpdateCipher_TO
                Record(Operation="CS_UpdateCipher", Time_Overhead=CS_UpdateCipher_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                enc_g_nodes, enc_g_edges = enc_updated_nodes, enc_updated_edges
                for cache in [n_addition_buf, e_addition_buf, n_deletion_buf, e_deletion_buf]:
                    cache.clear()
            # --------------------------------
            if query_or_not == "Yes":
                CS_CF_TO = time.perf_counter()
                cf = CuckooFilter(capacity=int(len(enc_updated_nodes | enc_updated_edges) / load_factor / 4))
                for enc_data in enc_updated_nodes | enc_updated_edges:
                    cf.insert(enc_data)
                CS_CF_TO = time.perf_counter() - CS_CF_TO
                CS_Subseq_TO += CS_CF_TO
                Record(Operation="CS_CF", Time_Overhead=CS_CF_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Reinsertion(cf, enc_updated_nodes | enc_updated_edges, False)
                # --------------------------------
                RP_Insert_S2R_TO = time.perf_counter()
                rq_nodes_set |= s_nodes_set
                rq_edges_set |= s_edges_set
                RP_Insert_S2R_TO = time.perf_counter() - RP_Insert_S2R_TO
                RP_Subseq_TO += RP_Insert_S2R_TO
                Record(Operation="RP_Insert_S2R", Time_Overhead=RP_Insert_S2R_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
                RP_BlndRq_TO = time.perf_counter()
                rq_nodes_inv, rq_edges_inv = [], []
                blnd_rq_nodes, blnd_rq_edges = [], []
                for rq_set, blnd_rq_list, rq_inv_list in [(rq_nodes_set, blnd_rq_nodes, rq_nodes_inv),
                                                          (rq_edges_set, blnd_rq_edges, rq_edges_inv)]:
                    for e in rq_set:
                        while True:
                            r = secrets.randbelow(N - 2) + 2
                            if gcd(r, N) == 1:
                                break
                        r_inv = mod_inverse(r, N)
                        blnd_e = (e_to_scalar(e) * pow(r, E, N)) % N
                        blnd_rq_list.append(blnd_e)
                        rq_inv_list.append(r_inv)
                RP_BlndRq_TO = time.perf_counter() - RP_BlndRq_TO
                RP_Subseq_TO += RP_BlndRq_TO
                Record(Operation="RP_BlndRq", Time_Overhead=RP_BlndRq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
                CS_EncRq_TO = time.perf_counter()
                enc_blnd_rq_nodes = [pow(blnd_node, D, N) for blnd_node in blnd_rq_nodes]
                enc_blnd_rq_edges = [pow(blnd_edge, D, N) for blnd_edge in blnd_rq_edges]
                CS_EncRq_TO = time.perf_counter() - CS_EncRq_TO
                CS_Subseq_TO += CS_EncRq_TO
                Record(Operation="CS_EncRq", Time_Overhead=CS_EncRq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
                RP_SeekCF_TO = time.perf_counter()
                enc_rq_nodes, enc_rq_edges = set(), set()
                for enc_blnd_rq_list, rq_inv_list, enc_rq_set in [(enc_blnd_rq_nodes, rq_nodes_inv, enc_rq_nodes),
                                                                  (enc_blnd_rq_edges, rq_edges_inv, enc_rq_edges)]:
                    for enc_blnd_rq, rq_inv in zip(enc_blnd_rq_list, rq_inv_list):
                        e = (enc_blnd_rq * rq_inv) % N
                        enc_rq_set.add(e)
                        if not cf.seek(e) :
                            print("😭Error: False negative phenomenon occurs")
                            sys.exit()
                RP_SeekCF_TO = time.perf_counter() - RP_SeekCF_TO

            # ———————————————————————————————— ✅️CORRECTNESS VERIFICATION SUCCESSFUL✅ ————————————————————————————————
            if query_or_not == "Yes":
                RP_Dif_TO = time.perf_counter()
                cf.delete(enc_rq_nodes | enc_rq_edges)
                RP_Dif_TO = time.perf_counter() - RP_Dif_TO
                RP_Subseq_TO += RP_Dif_TO
                Record(Operation="RP_Dif", Time_Overhead=RP_Dif_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
                RP_BlndQ_TO = time.perf_counter()
                q_nodes_inv, q_edges_inv = [], []
                blnd_q_nodes, blnd_q_edges = [], []
                for q_set, blnd_q_list, q_inv_list in [(q_nodes_set, blnd_q_nodes, q_nodes_inv),
                                                       (q_edges_set, blnd_q_edges, q_edges_inv)]:
                    for e in q_set:
                        while True:
                            r = secrets.randbelow(N - 2) + 2
                            if gcd(r, N) == 1:
                                break
                        r_inv = mod_inverse(r, N)
                        blnd_e = (e_to_scalar(e) * pow(r, E, N)) % N
                        blnd_q_list.append(blnd_e)
                        q_inv_list.append(r_inv)
                RP_BlndQ_TO = time.perf_counter() - RP_BlndQ_TO
                RP_Subseq_TO += RP_BlndQ_TO
                Record(Operation="RP_BlndQ", Time_Overhead=RP_BlndQ_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
                CS_EncQ_TO = time.perf_counter()
                enc_blnd_q_nodes = [pow(blnd_q_node, D, N) for blnd_q_node in blnd_q_nodes]
                enc_blnd_q_edges = [pow(blnd_q_edge, D, N) for blnd_q_edge in blnd_q_edges]
                CS_EncQ_TO = time.perf_counter() - CS_EncQ_TO
                CS_Subseq_TO += CS_EncQ_TO
                Record(Operation="CS_EncQ", Time_Overhead=CS_EncQ_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
                num_queries = len(enc_blnd_q_nodes) + len(enc_blnd_q_edges)
                FP_Rate = (2 * cf.bucket_size) / (2 ** cf.fp_size)
                FP_Threshold = math.ceil(num_queries * FP_Rate * 2)
                # --------------------------------
                _RP_SeekCF_TO = time.perf_counter()
                FP_Count = 0
                for enc_blnd_q_list, q_inv_set in [(enc_blnd_q_nodes, q_nodes_inv),
                                                   (enc_blnd_q_edges, q_edges_inv)]:
                    for enc_blnd_q, q_inv in zip(enc_blnd_q_list, q_inv_set):
                        e = (enc_blnd_q * q_inv) % N
                        if cf.seek(e):
                            print("🤔False positive phenomenon occurs")
                            FP_Count += 1
                _RP_SeekCF_TO = time.perf_counter() - _RP_SeekCF_TO
                RP_SeekCF_TO += _RP_SeekCF_TO
                RP_Subseq_TO += RP_SeekCF_TO
                if FP_Count > FP_Threshold:
                    print("😭Error: The number of observed false positives significantly exceeds the theoretical rate")
                    sys.exit()
                # --------------------------------
                Record(Operation="RP_SeekCF", Time_Overhead=RP_SeekCF_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Record(Operation="DO_Subseq", Time_Overhead=DO_Subseq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Record(Operation="RP_Subseq", Time_Overhead=RP_Subseq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                Record(Operation="CS_Subseq", Time_Overhead=CS_Subseq_TO, Update_Type=update_type, Query_or_Not=query_or_not)
                # --------------------------------
            g_nodes_set, g_edges_set = updated_nodes_set, updated_edges_set
            current_iteration += 1
            if current_iteration == max_iteration:
            # if current_iteration == commit_interval + 1:
                print(f"🤔RP initiated queries for a total of \033[31m{count_dict[('Addition', 'Yes')]}\033[0m rounds of append-type graph updates, while \033[31m{count_dict[('Addition', 'No')]}\033[0m rounds of append-type graph updates were made without query initiation")
                print(f"🤔RP also initiated queries for \033[31m{count_dict[('Deletion', 'Yes')]}\033[0m rounds of remove-type graph updates, whereas \033[31m{count_dict[('Deletion', 'No')]}\033[0m rounds of remove-type graph updates were performed without initiating queries\n")
                print("——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————")
                Print()
            time.sleep(1)

if __name__ == "__main__":
    Triple_Verification()
