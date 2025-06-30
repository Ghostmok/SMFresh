
本代码库是论文 "SMFresh: A Verifiable Subgraph Matching Scheme with Freshness Assurance for Outsourced Graph Databases" 的官方实现。

# 1. 环境与依赖 (Prerequisites)

在运行本代码前，请确保您已安装Python 3.9+ 及以下依赖库：
* pycryptodome
* numpy
* sympy
* gmpy2
* tqdm

您可以通过pip进行安装：
`pip install pycryptodome sympy gmpy2 tqdm numpy`
-----------------------------------



# 2. 数据集准备 (Dataset Setup)

本实验使用了 Stanford Large Network Dataset Collection (SNAP) 中的真实世界图数据集。

1. 请将以下数据集解压到您的项目目录中：
   * Email (`snap-Email-Enron.txt`)
   * YouTube (`snap-com-youtube.txt`)
   * Patents (`snap-cit-Patents`)

2. 修改`Graph_Operation.py`代码中的`path_prefix`变量。

3. 运行脚本。

所有实验的入口文件均为 `Triple_Verification.py`。



----------------------------------------------------------------------
场景一：在 'em' 和 'yt' 数据集上进行性能测试
----------------------------------------------------------------------

保持`Triple_Verification.py`文件的配置为默认状态后运行。

* `GDB_INDEX = 0`             （0对应em数据集；1对应yt数据集）
* `SUB_INDEX = "3n3e"`        （可选其他查询图）



----------------------------------------------------------------------
场景二：测试SMFresh在 'pt' 数据集上的性能
----------------------------------------------------------------------

此场景用于评估SMFresh在`pt`这一大规模稀疏图上的可扩展性。

   * 1.修改以下变量：
      *     GDB_INDEX = 0        -------->   GDB_INDEX = 2
      *     SUB_INDEX = "3n3e"   -------->   SUB_INDEX = "5n7e"

   * 2.取消注释，以启用基于`sample_size`的图采样：
      *     Line32: sample_size = 80 * 1000 （取消本行注释）
      *     Line71: adj_list = adjacency_list(g_nodes_set, g_edges_set) （取消本行注释）
      *     Line72, Line 73: g_nodes_set, g_edges_set = sample_graph(adj_list, sample_size, subgraphs[filename[GDB_INDEX]][SUB_INDEX][0], subgraphs[filename[GDB_INDEX]][SUB_INDEX][1]) （取消本行注释）

   * 3.您现在可以通过修改第32行的 `sample_size` 变量来控制`pt`的规模。

   * 4.运行脚本。



----------------------------------------------------------------------
场景三：通过控制变量测试SMFresh的性能
----------------------------------------------------------------------

此场景用于进行更细粒度的性能分析。

   * 1.撤销场景二中的所有修改，恢复到默认配置。

   * 2.修改以下代码：
      *     注释第31行：`SUB_INDEX = "3n3e"`
      *     取消注释第36行：`# num_subgraph_edges = 100`
      *     注释第100行和第463行：`q_nodes_set, q_edges_set = subgraphs[filename[GDB_INDEX]][SUB_INDEX]   &   q_nodes_set, q_edges_set = subgraphs[filename[GDB_INDEX]][SUB_INDEX]`
      *     取消注释第101行和第464行：`# q_nodes_set, q_edges_set = generate_subgraph(g_nodes_set, g_edges_set, num_subgraph_edges)   &   # q_nodes_set, q_edges_set = generate_subgraph(updated_nodes_set, updated_edges_set, num_subgraph_edges)`

   * 3.您现在可以通过修改第34-36行的 `num_s_edges、num_update_edges、num_subgraph_edges` 变量来控制不同的实验参数。

   * 4.运行脚本。



# 开源许可 (License)
本项目采用 MIT 许可。