import sys


dicts = {"Init": {"Mapping": [],
                  "DO_Insert_S2G": [],
                  "DO_TreeOp": [],
                  "DO_SignRoot": [],
                  "CS_TreeOp": [],
                  "CS_GenProof": [],
                  "RP_VerifyProof": [],
                  "RP_Insert_S2R": [],
                  "CS_EncG": [],
                  "CS_CF": [],
                  "RP_BlndRq": [],
                  "CS_EncRq": [],
                  "RP_Dif": [],
                  "RP_BlndQ": [],
                  "CS_EncQ": [],
                  "RP_SeekCF": [],
                  "DO_Init": [],
                  "RP_Init": [],
                  "CS_Init": []},
         "DO_Mapping": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_Mapping": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "DO_Insert_S2U": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "DO_TreeOp": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "DO_SignRoot": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_TreeOp": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_GenHomo": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_GenProof": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_VerifyProof": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_EncNew": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_UpdateCipher": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_CF": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_Insert_S2R": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_BlndRq": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_EncRq": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_Dif": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_BlndQ": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_EncQ": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_SeekCF": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "DO_Subseq": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "RP_Subseq": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}},
         "CS_Subseq": {"Addition": {"Yes": [], "No": []}, "Deletion": {"Yes": [], "No": []}}}


def Record(Operation, Time_Overhead, Update_Type=None, Query_or_Not=None):
    if Update_Type is None:
        dicts["Init"][Operation].append(Time_Overhead)
    else:
        dicts[Operation][Update_Type][Query_or_Not].append(Time_Overhead)


def Print():
    DO_Ops = [op for op in dicts["Init"].keys() if op.startswith("DO_") or op == "Mapping"]
    RP_Ops = [op for op in dicts["Init"].keys() if op.startswith("RP_") or op == "Mapping"]
    CS_Ops = [op for op in dicts["Init"].keys() if op.startswith("CS_")]
    print(f"\nTime overheads incurred by \033[33mDO\033[0m(📂) during the verification of the outsourcing cycle")
    DO_DATA = []
    for op in DO_Ops:
        if dicts["Init"][op]:
            DO_DATA.append((op, dicts["Init"][op][0]))
    rows = 1
    cols = 5
    for i in range(rows):
        Data = []
        for j in range(cols):
            idx = i * cols + j
            if idx < len(DO_DATA):
                op, to = DO_DATA[idx]
                Data.append(f"{op}: {to:.6f}".ljust(30))
            else:
                Data.append("".ljust(30))
        print("".join(Data))
    print(f"\nTime overheads incurred by \033[33mRP\033[0m(👨🏻‍💻) during the verification of the outsourcing cycle")
    RP_DATA = []
    for op in RP_Ops:
        if dicts["Init"][op]:
            RP_DATA.append((op, dicts["Init"][op][0]))
    rows = 2
    cols = 4
    for i in range(rows):
        Data = []
        for j in range(cols):
            idx = i * cols + j
            if idx < len(RP_DATA):
                op, to = RP_DATA[idx]
                Data.append(f"{op}: {to:.6f}s".ljust(30))
            else:
                Data.append("".ljust(30))
        print("".join(Data))
    print(f"\nTime overheads incurred by \033[33mCS\033[0m(🖥️) during the verification of the outsourcing cycle")
    CS_DATA = []
    for op in CS_Ops:
        if dicts["Init"][op]:
            CS_DATA.append((op, dicts["Init"][op][0]))
    rows = 2
    cols = 4
    for i in range(rows):
        Data = []
        for j in range(cols):
            idx = i * cols + j
            if idx < len(CS_DATA):
                op, to = CS_DATA[idx]
                Data.append(f"{op}: {to:.6f}s".ljust(30))
            else:
                Data.append("".ljust(30))
        print("".join(Data))
    emoji_dict = {("Addition", "Yes"): "➕🔗✔️", 
                  ("Addition", "No"): "➕🔗✖️", 
                  ("Deletion", "Yes"): "➖🔗✔️", 
                  ("Deletion", "No"): "➖🔗✖️"}
    for update_type in ["Addition", "Deletion"]:
        for query_or_not in ["Yes"]:
            emoji = emoji_dict[(update_type, query_or_not)]
            DO_Ops = [op for op in dicts.keys() if op.startswith("DO_") and op != "Init"]
            RP_Ops = [op for op in dicts.keys() if op.startswith("RP_") and op != "Init"]
            CS_Ops = [op for op in dicts.keys() if op.startswith("CS_") and op != "Init"]
            DO_DATA = []
            for op in DO_Ops:
                if dicts[op][update_type][query_or_not]:
                    avg_to = sum(dicts[op][update_type][query_or_not]) / len(dicts[op][update_type][query_or_not])
                    DO_DATA.append((op, dicts[op][update_type][query_or_not], avg_to, len(dicts[op][update_type][query_or_not])))
            RP_DATA = []
            for op in RP_Ops:
                if dicts[op][update_type][query_or_not]:
                    avg_to = sum(dicts[op][update_type][query_or_not]) / len(dicts[op][update_type][query_or_not])
                    RP_DATA.append((op, dicts[op][update_type][query_or_not], avg_to, len(dicts[op][update_type][query_or_not])))
            CS_DATA = []
            for op in CS_Ops:
                if dicts[op][update_type][query_or_not]:
                    avg_to = sum(dicts[op][update_type][query_or_not]) / len(dicts[op][update_type][query_or_not])
                    CS_DATA.append((op, dicts[op][update_type][query_or_not], avg_to, len(dicts[op][update_type][query_or_not])))
            print("\n——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————")
            if DO_DATA:
                print(f"\n{emoji}Time overheads incurred by \033[33mDO\033[0m(📂) during the verification of subsequent graph data update iterations")
                rows = 1
                cols = 5
                for i in range(rows):
                    Data = []
                    for j in range(cols):
                        idx = i * cols + j
                        if idx < len(DO_DATA):
                            op, to_list, avg_to, to_list_length = DO_DATA[idx]
                            Data.append(f"{op}: {avg_to:.6f}s".ljust(30))
                        else:
                            Data.append("".ljust(30))
                    print("".join(Data))
                print("\033[33m↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓\033[0m")
                for op, to_list, avg_to, to_list_length in DO_DATA:
                    print(f"length: {to_list_length}, {op}: {[f'{num:.6f}' for num in to_list]}")
            if RP_DATA:
                print(f"\n\n{emoji}Time overheads incurred by \033[33mRP\033[0m(👨🏻‍💻) during the verification of subsequent graph data update iterations")
                rows = 2
                cols = 5
                for i in range(rows):
                    Data = []
                    for j in range(cols):
                        idx = i * cols + j
                        if idx < len(RP_DATA):
                            op, to_list, avg_to, to_list_length = RP_DATA[idx]
                            Data.append(f"{op}: {avg_to:.6f}s".ljust(30))
                        else:
                            Data.append("".ljust(30))
                    print("".join(Data))
                print("\033[33m↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓\033[0m")
                for op, to_list, avg_to, to_list_length in RP_DATA:
                    print(f"length: {to_list_length}, {op}: {[f'{num:.6f}' for num in to_list]}")
            if CS_DATA:
                print(f"\n\n{emoji}Time overheads incurred by \033[33mCS\033[0m(🖥️) during the verification of subsequent graph data update iterations")
                rows = 2 if query_or_not == "Yes" else 1
                cols = 4 if query_or_not == "Yes" else 4
                for i in range(rows):
                    Data = []
                    for j in range(cols):
                        idx = i * cols + j
                        if idx < len(CS_DATA):
                            op, to_list, avg_to, to_list_length = CS_DATA[idx]
                            Data.append(f"{op}: {avg_to:.6f}s".ljust(30))
                        else:
                            Data.append("".ljust(30))
                    print("".join(Data))
                print("\033[33m↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓\033[0m")
                for op, to_list, avg_to, to_list_length in CS_DATA:
                    print(f"length: {to_list_length}, {op}: {[f'{num:.6f}' for num in to_list]}")


def get_size(o, ids=None):
    if ids is None:
        ids = set()
    if id(o) in ids:
        return 0
    r = sys.getsizeof(o)
    ids.add(id(o))
    if isinstance(o, dict):
        r += sum(get_size(k, ids) + get_size(v, ids) for k, v in o.items())
    elif hasattr(o, '__iter__') and not isinstance(o, (str, bytes, bytearray)):
        r += sum(get_size(i, ids) for i in o)
    if hasattr(o, '__dict__'):
        r += get_size(o.__dict__, ids)
    return r


def format_size(size):
    power = 1024
    n = 0
    power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB'}
    while size >= power and n < len(power_labels) - 1:
        size /= power
        n += 1
    return f"{size:.2f} {power_labels[n]}"


def print_table(cs_overhead, rp_overhead):
    col_width = 15
    RED = '\033[91m'
    RESET = '\033[0m'
    cs_total = sum(cs_overhead.values())
    cs_data = cs_overhead.copy()
    cs_data['Total Overhead'] = cs_total
    cs_headers = list(cs_data.keys())
    cs_values = [format_size(v) for v in cs_data.values()]
    cs_header_row = []
    for header in cs_headers:
        if header == 'Total Overhead':
            cs_header_row.append(f"{RED}{header:<{col_width}}{RESET}")
        else:
            cs_header_row.append(f"{header:<{col_width}}")
    print("".join(cs_header_row))
    print("-" * (len(cs_headers) * col_width))
    cs_value_row = []
    for i, value in enumerate(cs_values):
        if i == len(cs_values) - 1:
            cs_value_row.append(f"{RED}{value:<{col_width}}{RESET}")
        else:
            cs_value_row.append(f"{value:<{col_width}}")
    print("".join(cs_value_row))
    print()
    rp_total = sum(rp_overhead.values())
    rp_data = rp_overhead.copy()
    rp_data['Total Overhead'] = rp_total
    rp_headers = list(rp_data.keys())
    rp_values = [format_size(v) for v in rp_data.values()]
    rp_header_row = []
    for header in rp_headers:
        if header == 'Total Overhead':
            rp_header_row.append(f"{RED}{header:<{col_width}}{RESET}")
        else:
            rp_header_row.append(f"{header:<{col_width}}")
    print("".join(rp_header_row))
    print("-" * (len(rp_headers) * col_width))
    rp_value_row = []
    for i, value in enumerate(rp_values):
        if i == len(rp_values) - 1:
            rp_value_row.append(f"{RED}{value:<{col_width}}{RESET}")
        else:
            rp_value_row.append(f"{value:<{col_width}}")
    print("".join(rp_value_row))
