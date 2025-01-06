# CommitShield
A Tool for Tracking Vulnerability Introduction and Fixes in Version Control Systems

# datasets
- In the VFD file, we collected 681 vulnerability fix data and 1118 non-vulnerability fix data.
- In the VID file, we cleaned the data in the V-SZZ algorithm and obtained data containing 284 vulnerabilities introduced.

# launch
- To make our tool as easy to run as possible, you can obtain the GitHub API key from GitHub;  
- Obtain the LLM API key from the deep seek official website. And replace the corresponding tokens in the file. Execute the following command:
`python vul_fix_check.py`
`python vul_intro_check.py`

# evaluation
The effectiveness of CommitShield in VFD:  
| Approach    | Model    | Parameter Size | Precision | Recall | F1-score |
|-------------|----------|----------------|-----------|--------|----------|
| Baseline    | Deep-Seek| 236B           | 0.62      | 0.94   | 0.75     |
| VulFixMiner | CodeBert | 125M           | 0.58      | 0.22   | 0.32     |
| VulCurator  | CodeBert | 125M           | 0.62      | 0.19   | 0.29     |
| CommitShield| Deep-Seek| 236B           | 0.81      | 0.96   | 0.88     |

The effectiveness of CommitShield in VID:  
| Approach    | Precision| Recall         | F1-score  |
|-------------|----------|----------------|-----------|
| V-SZZ       | 0.52     | 0.79           | 0.63      |
| AG-SZZ      | 0.49     | 0.63           | 0.55      |
| B-SZZ       | 0.46     | 0.67           | 0.55      |
| L-SZZ       | 0.55     | 0.47           | 0.51      |
| MA-SZZ      | 0.43     | 0.63           | 0.51      |
| R-SZZ       | 0.69     | 0.59           | 0.64      |
| CommitShield| 0.74     | 0.82           | 0.78      |


# citation
If you reference our work or use our tools, the reference information is as follows:  
```
@unpublished{author:2025,  
  author = {Zhaonan, Wu. and Yanjie, Zhao. and Chen, Wei. and Zirui, Wan. and Yue, Liu. and Haoyu, Wang.},  
  title = {CommitShield: Tracking Vulnerability Introduction and Fix in Version Control Systems},  
  year = {2024}  
}
```
