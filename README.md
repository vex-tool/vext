# Vulnerability Exploration Tool

The Vulnerability EXploration Tool (VEXT) is provided to promote the research in the vulnerability ecosystem.
<img src="./img/vex-tool.png" style="float:right;height:200;display:block;">



## Quickstart

 - Download the latest release or `git clone git@github.com:vex-tool/vext.git`
 - `pip install -r requirements.txt`
 - `python3 bootstrap.py` 
 - start and interactive `ipython` session or explore examples in the notebooks folder with `jupyter-lab`

## Evaluate

The completeness of the dataset can be assessed by comparing the CWE classification of the dataset with the CWE classifications represented with the entire corpus of CVEs from the same time period.
For example, we used the tool to assess the completeness of the Secbench dataset compared to the most prevalent CWE categories of the year.

![SecBench completeness](./img/secbench2016.png)

### Explore trends in weakness patterns
Starting with a high level overview of the weakness categories, this tool enables practitioners to explore vulnerability reports that are associated with different parts of the weakness taxonomy.

![](./img/cwe-pillars.png)
![](./img/cwe-pillars-logscale.png)
![](./img/284.png)
![](./img/pillar284.png)
![](./img/285.png)
