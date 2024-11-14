import requests
import json
import os
import subprocess
import re
import shutil
import tokenize
import io
from openai import OpenAI
from urllib.parse import urlparse
from datetime import datetime
from collections import Counter
from tree_sitter import Language, Parser



token = 'Your_Token'
clone_dir = 'repos/'
def get_commit_link(repo_url):
    url = repo_url.replace("github.com", "api.github.com/repos").replace("commit", "commits")
    parsed_url = urlparse(url)
    path = parsed_url.path
    parts = path.split('/')
    class Rep:
        def __init__(self, OWNER, REPO, commit_id):
            self.OWNER = OWNER
            self.REPO = REPO
            self.commit_id = commit_id
    
    for i, part in enumerate(parts):
        if i == 2:
            OWNER = part
        elif i == 3:
            REPO = part
        elif i == 5:
            commit_id = part
    
    rep = Rep(OWNER, REPO, commit_id)
    
    return url, rep


def get_commit_information(repo_url, rep):

    response = requests.get(repo_url, headers={'Authorization': f'token {token}'})
    if response.status_code == 200:
    
        commit_info = response.json()
        commit = {}
        commit['sha'] = commit_info['sha']
        commit['message'] = commit_info['commit']['message']
        commit['url'] = commit_info['url']
        commit['status'] = commit_info['stats']
        commit['files'] = commit_info['files']
        commit['parents_commit'] = commit_info['parents'][0]['url']
        commit['parents_sha'] = commit_info['parents'][0]['sha']
        commit['comments_url'] = commit_info['comments_url']
        return commit
    else:
        print("Failed to get commit information:", response.status_code)
        return 0
    
def patch_classify(commit_infor):
    file_numbers = len(commit_infor['files'])
    if file_numbers == 1:
        classify_flag = 1
        return classify_flag
        '''modify_lines = commit_infor['status']['total']
        if modify_lines <= 8:
            judge_func = LLM_step2(commit_infor['files'][0]['patch'])
            if judge_func == 1:
                classify_flag = 1
            else:
                classify_flag = 2
        elif modify_lines > 8:
            classify_flag = 2
        else:
            print("Patch is empty!!!")
            classify_flag = 0'''
    elif file_numbers > 1:
        patch_num = 0
        new_patches = []
        for i in range(len(commit_infor['files'])):
            patch = commit_infor['files'][i]
            judge = LLM_relevant(commit_infor['message'], patch)
            if judge == 1:
                new_patches.append(commit_infor['files'][i])
                patch_num = patch_num + 1
                print("Relevant patch!!!", patch['filename'])
            else:
                print("Unrelevant patch!!!", patch['filename'])
        if patch_num > 1:
            classify_flag = 2
            return classify_flag, new_patches
        elif patch_num == 1:
            classify_flag = 1
            return classify_flag, new_patches
            '''modify_lines = new_patches[0]['changes']
            if modify_lines <= 8:
                judge_func = LLM_step2(commit_infor['files'][0]['patch'])
                if judge_func == 1:
                    classify_flag = 1
                else:
                    classify_flag = 2
                return classify_flag, new_patches
            elif modify_lines > 8:
                classify_flag = 2
                return classify_flag, new_patches
            else:
                print("Patch is empty!!!")
                classify_flag = 0
                return classify_flag'''
        else:
            classify_flag = 0
            new_patches = commit_infor['files']
            print("Error!!! NO PATCHES!")
            return classify_flag, new_patches
    

def get_issues(message, rep):
    match_obj = re.search(r'#(\d+)', message)
    if match_obj:
        number = match_obj.group(1)  
        issue_url = 'https://api.github.com/' + 'repos/' + rep.OWNER + '/' + rep.REPO + '/' + 'issues/' + number
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        response = requests.get(issue_url, headers=headers)
        if response.status_code == 200:
            issue_data = response.json()
            issue_description = issue_data.get('title', 'No description provided.')
            print("GET ISSUE!!!")
            return issue_description
        else:
            print(f'Failed to fetch issue: {response.status_code}')
            issue_description = 'NULL'
            return issue_description

def get_prs(message, rep):
    match_obj = re.search(r'#(\d+)', message)
    if match_obj:
        number = match_obj.group(1)  
        pr_url = 'https://api.github.com/' + 'repos/' + rep.OWNER + '/' + rep.REPO + '/' + 'pulls/' + number
        headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }
        response = requests.get(pr_url, headers=headers)
        if response.status_code == 200:
                pr_data = response.json()
                pull_description =pr_data.get('body', 'No description provided.')
                print("GET PULL REQUEST!!!")
                return pull_description
        else:
            print(f'Failed to fetch pr: {response.status_code}')
            pr_description = 'NULL'
            return pr_description


def get_comment(comment_url):
    url = comment_url
    headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        comment_data = response.json()
        if comment_data == '':
            comment_description = 'NULL'
            return comment_description
        else:
            comment_description = []
            for i in range(len(comment_data)):
                comment_description.append(comment_data[i]['body'])
            return comment_description
    else:
        print(f'Failed to fetch issue: {response.status_code}')
        comment_description = 'NULL'
        return comment_description

def LLM_describe(description):
    basic = description['basic']
    issue = description['issue']
    pr = description['pr']
    comments = description['comment']
    client = OpenAI(
        api_key="Your Key_Api",
        base_url="https://api.deepseek.com",
    )
    prompt = {
        "basic_description":basic,
        "issue_description":issue,
        "pr_description":pr,
        "comment_description":comments
    }
    system_prompt = """You are an excellent summary and analysis expert, and users will provide you with four types of descriptive information. Not every type of descriptive information will have content. Please summarize a sentence that is as accurate and comprehensive as possible based on the descriptive information you have obtained."""
    

    user_prompt = "I will provide you with four types of information, which may not always contain specific content at the same time. Please generate a more accurate and comprehensive description based on the information you have obtained, which only needs to include the content of the role or impact class. The basic description is {basic_description}. The problem description is {issue_description}, the pull request description is {pr_description}, and the comment description is {comment_description}. Please note that you only need to provide a description, without declaring which descriptions are missing.".format(**prompt)

    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]
    response = client.chat.completions.create(
        model="deepseek-coder",
        messages=messages,
        max_tokens=1024,
        temperature=0.7,
        stream=False,
    )
    return response.choices[0].message.content

def LLM_relevant(message, patch):
    client = OpenAI(
        api_key="Your Key_Api",
        base_url="https://api.deepseek.com",
    )
    prompt = {
        "description":message,
        "patch":patch
    }
    system_prompt = """
    You are a patch analysis expert. The user will provide you with a description of a commit and a patch for one of its files. Please use this information to determine if the patch is relevant to the problem being described. If relevant, please output 1; If not relevant, please output 0. Please output in JSON format. The JSON format is as follows.
    If there are modifications to the test or test case in the patch, it is also considered an unrelated patch.
    EXAMPLE JSON OUTPUT:
    {
        "answer":,
        "analyze":
    }
    """


    user_prompt = "I will provide you with the description information in a commit and the modifications made to one of the files in the patch of this commit. Please check if the modifications made to the file are related to the description information. The description is {description}. The patch is {patch}.".format(**prompt)
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]

    response = client.chat.completions.create(
        model="deepseek-coder",
        messages=messages,
        max_tokens=1024,
        temperature=0.7,
        stream=False,
        response_format={
            'type': 'json_object'
        }
    )
    data_json = json.loads(response.choices[0].message.content)
    return data_json['answer']

def LLM_step2(patch):
    client = OpenAI(
        api_key="Your Key_Api",
        base_url="https://api.deepseek.com",
    )
    prompt = {
        "patches":patch
    }
    system_prompt = """
    You are a code analysis expert, and the user will provide you with a patch. Please determine whether the code modifications in the patch are within a function based on the patch information. If all code modifications are within one function, please output 1; If there are two or more, please output 0. Please output the results in JSON format.
    EXAMPLE JSON OUTPUT:
    {
        "answer":,
        "analyze":
    }
    """
    user_prompt = "I will provide you with a commit patch information, so please determine whether all the code changes in the patch are within one function based on the patch information. The patch is {patches}.".format(**prompt)
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]

    response = client.chat.completions.create(
        model="deepseek-coder",
        messages=messages,
        max_tokens=1024,
        temperature=0.7,
        stream=False,
        response_format={
            'type': 'json_object'
        }
    )
    data_json = json.loads(response.choices[0].message.content)
    return data_json['answer']

def LLM_impact(message, patch, func):
    client = OpenAI(
        api_key="Your Key_Api",
        base_url="https://api.deepseek.com",
    )
    system_prompt = """
    You are a code patch analysis expert, and the user will provide you with a commit patch and the function where the patch is located. If the function exists, it is the function where the patch is located. Please judge whether the impact of the modified statement by the patch is limited to this function based on the patch and its function. If it is, please output 1. If you think that the patch may have an impact on other functions that are not provided, please output 1; If no function is provided to you, i.e. the provided function is empty, please determine its impact range based on the patch content. If it is limited to within the function, output 1. If it may affect other functions, output 0. 
    Please output in JSON format. The content of the target JSON file is as follows:  
    {
        "answer":
    }
    """
    user_prompt = """
    I will provide you with the following information:
    1. Description of commit: {description}
    2. Patch for commit: {patches}
    3. Function where patch is located: {functions}
    Please judge whether the impact of changes in this patch is limited to the function where the patch is located based on the above information.
    """.format(description = message, patches = patch, functions = func)
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]
    response = client.chat.completions.create(
        model="deepseek-coder",
        messages=messages,
        max_tokens=1024,
        temperature=0.7,
        stream=False,
        response_format={
            'type': 'json_object'
        }
    )
    data_json = json.loads(response.choices[0].message.content)
    return data_json

def LLM_analyze(description_pro, patch, patch_context):
    client = OpenAI(
        api_key="Your Key_Api",
        base_url="https://api.deepseek.com",
    )
    prompt = {
        "patches":patch,
        "context":patch_context
    }
    system_prompt = """
    You are the vulnerability repair and detection expert responsible for analyzing and submitting patches. You can determine whether this commit is a vulnerability fix commit based on the description information submitted and the modifications made in the patch submitted. The definition of vulnerability repair in commit is as follows: there are known security vulnerabilities or runtime errors in the code before patch modification, and the vulnerabilities or errors are resolved after modification in the patch. This vulnerability is a known vulnerability, and if the purpose of patch implementation is to upgrade functionality, secure defense, fix code format, or fix potential vulnerabilities (the code before modification has no known vulnerabilities), then this commit cannot be considered a vulnerability repair commit.    Please output in JSON format. The content of the target JSON file is as follows:
    {
        "answer":,
        "analyze":
    }     
    """
    user_prompt = """
    I will provide you with the following information:
    1. Submission instructions: {description}
    2. Submit patches: {patches}
    3. Function contexts that may be affected by patches: {contexts}
    Please use this information to determine if the patch fixes known vulnerabilities that may exist in other function contexts. Please note that the definitions of vulnerability fixes, feature upgrades and improvements, and security protection upgrades are not considered as vulnerability fixes.
    If the context information is empty, please identify it based on the description of this commit and its patch.If the description of a commit contains keywords such as fix, bug, etc., these commits tend to be vulnerability fixes. Please accurately identify this part of the content.
    """.format(description = description_pro, patches = patch, contexts = patch_context)
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]
    response = client.chat.completions.create(
        model="deepseek-coder",
        messages=messages,
        max_tokens=1024,
        temperature=0.7,
        stream=False,
        response_format={
            'type': 'json_object'
        }
    )
    data_json = response.choices[0].message.content
    return data_json

def LLM_analyze_without_joern(description_pro, patch, function):
    client = OpenAI(
        api_key="Your Key_Api",
        base_url="https://api.deepseek.com",
    )
    system_prompt = """
    You are the vulnerability repair and detection expert responsible for analyzing and submitting patches. You can determine whether this commit is a vulnerability fix commit based on the description information submitted and the modifications made in the patch submitted. The definition of vulnerability repair in commit is as follows: there are known security vulnerabilities or runtime errors in the code before patch modification, and the vulnerabilities or errors are resolved after modification in the patch. This vulnerability is a known vulnerability, and if the purpose of patch implementation is to upgrade functionality, secure defense, fix code format, or fix potential vulnerabilities (the code before modification has no known vulnerabilities), then this commit cannot be considered a vulnerability repair commit.    Please output in JSON format. The content of the target JSON file is as follows:
    {
        "answer":,
        "analyze":
    }     
    """
    user_prompt = """
    I will provide you with the following information:
    1. Submission description: {description}
    2. Submit patches: {patches}
    3. Function where the patch is located: {functions}
    Please determine whether the patch has fixed existing security vulnerabilities based on the above information. Please note that the definition of vulnerability repair, functional upgrades and improvements, and security protection upgrades are not considered as vulnerability repairs.    
    If the functions information is empty, please make a judgment based on the description and content of the patch.If the description of a commit contains keywords such as fix, bug, etc., these commits tend to be vulnerability fixes. Please accurately identify this part of the content.
    """.format(description = description_pro, patches = patch, functions = function)
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}]
    response = client.chat.completions.create(
        model="deepseek-coder",
        messages=messages,
        max_tokens=1024,
        temperature=0.7,
        stream=False,
        response_format={
           'type': 'json_object'
        }
    )
    data_json = response.choices[0].message.content
    return data_json

def description_update(commit_infor, rep):
    description = {}
    description['basic'] = commit_infor['message']
    issue_descrption = get_issues(description['basic'], rep)
    description['issue'] = issue_descrption
    pr_descrption = get_prs(description['basic'], rep)
    description['pr'] = pr_descrption
    comment_url = commit_infor['comments_url']
    comment_descrption = get_comment(comment_url)
    description['comment'] = comment_descrption
    description_pro = LLM_describe(description)
    return description_pro

def get_line(patch):
    lines = patch.splitlines()
    pattern = r'[-+]?\d+,\d+'
    pattern2 = r'[-+]\d+,\d+'
    modify = []
    for line in lines:
        match = 0

        if re.search(pattern, line):
            match = 1
        if match == 1:
            parts = line.split()
            for part in parts:
                if re.match(pattern2, part):
                    number, column = part.split(',')
                    sign = '-' if part[0] == '-' else '+'
                    if sign == '-':
                        patch_start_line = abs(int(number))
                        patch_start_line = patch_start_line + 3
                        modify.append(patch_start_line)
    return modify

def get_download_url(url, parent_id):
    parts = url.split('/')
    son_id = parts[6]
    download_url = url.replace(son_id, parent_id)
    return download_url

def file_download(url, save_path):
    headers = {
        "Authorization": 'Your_Token' 
    }
    try:
        
        response = requests.get(url, headers=headers)

        
        if response.status_code == 200:
            
            with open(save_path, 'wb') as file:
                file.write(response.content)
        else:
            print(f"Failed: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

def get_func(file_path, line_number):
    Language.build_library(
        'build/my-languages.so',
        [
            'tree-sitter/vendor/tree-sitter-cpp'
        ]
    )
    CPP_LANGUAGE = Language('build/my-languages.so', 'cpp')
    parser = Parser()
    parser.set_language(CPP_LANGUAGE)
    
    with open(file_path, 'r', errors='ignore') as file:
        lines = file.read()
    code = lines
    tree = parser.parse(bytes(code,"utf-8"))
    root_node = tree.root_node
    code = code.split("\n")
    
    for child_node in root_node.children:
        if child_node.type == "function_definition":
            function_start_line = child_node.start_point[0]
            function_end_line = child_node.end_point[0]
            if function_start_line != function_end_line:
                function_code = code[function_start_line:function_end_line + 1]
                
                function_code = "\n".join(function_code)
                if (function_start_line < line_number < function_end_line + 1):
                    print("Find!!!!", function_start_line, function_end_line + 1)
                    function_name_line = code[function_start_line]
                    if "(" in function_name_line:
                        match = re.search(r'\s+([^\s()]+)\(', function_name_line)
                        match_2 = re.search(r'([^\s]+)\(', function_name_line)
                        match_3 = re.search(r'\s+(?:\*\s*)?([^\s()]+)\(', function_name_line) 
                        if match:   
                            function_name = match.group(1)
                        elif match_2:
                            function_name = match_2.group(1)
                        else:
                            function_name = 'NULL'

                        if match_3:
                            function_name = match_3.group(1)
                        
                        return function_code,function_name
                    else:
                        function_name_line = code[function_start_line + 1]
                        match = re.search(r'\s+([^\s()]+)\(', function_name_line)
                        match_2 = re.search(r'([^\s]+)\(', function_name_line)
                        match_3 = re.search(r'\s+(?:\*\s*)?([^\s()]+)\(', function_name_line) 
                        if match:   
                            function_name = match.group(1)
                        elif match_2:
                            function_name = match_2.group(1)
                        
                        else:
                            function_name = 'NULL'
                        if match_3:
                            function_name = match_3.group(1)
                            
                        return function_code,function_name

            else:
                function_code = code[function_start_line]
                function_name = 'NULL'
                return function_code,function_name
            
        elif child_node.type != "function_definition":
            for child in child_node.children:
                function_code, function_name = find_function_define(child, code, line_number)
                if function_name != 'NULL' and function_code != 'NULL':
                    return function_code,function_name
            function_code = 'NULL'
            function_name = 'NULL' 
            
    function_code = 'NULL'
    function_name = 'NULL'
    return function_code,function_name    


def find_function_define(root_node, code, line_number):
    if root_node.type != "function_definition":
        for child in root_node.children:
            function_code,function_name = find_function_define(child, code, line_number)
            if function_name != 'NULL' and function_code != 'NULL':
                return function_code,function_name
        function_code = 'NULL'
        function_name = 'NULL'    
        return function_code,function_name
    elif root_node.type == "function_definition":
        function_start_line = root_node.start_point[0]
        function_end_line = root_node.end_point[0]

        if function_start_line != function_end_line:
            function_code = code[function_start_line:function_end_line + 1]
            
            function_code = "\n".join(function_code)
            if (function_start_line < line_number < function_end_line + 1):
                print("Find!!!!", function_start_line, function_end_line + 1)
                function_name_line = code[function_start_line]
                match = re.search(r'\s+([^\s()]+)\(', function_name_line)
                match_2 = re.search(r'([^\s]+)\(', function_name_line)
                if match:   
                    function_name = match.group(1)
                elif match_2:
                    function_name = match_2.group(1)
                else:
                    function_name = 'NULL'
                return function_code,function_name
            else:
                function_code = 'NULL'
                function_name = 'NULL'
                return function_code,function_name
        else:
            function_code = code[function_start_line]
            function_name = 'NULL'
            return function_code,function_name
    else:
        function_code = 'NULL'
        function_name = 'NULL'    
        return function_code,function_name


def url_change(url):
    match = re.search(r'github\.com[:/](.+?)/commit', url)
    if match:
        repo_path = match.group(1)
        return f"https://github.com/{repo_path}.git"
    else:
        raise ValueError("Invalid GitHub commit URL")

def get_repo(url):
    parsed_url = urlparse(url)
    repo_path = parsed_url.path.lstrip('/')
    parts = repo_path.split('/')
    repo_field = parts[1]
    return repo_field

def repo_download(url_git, repo, sha):
    download_path = clone_dir + repo
    if not os.path.exists(download_path):
        cmd = ['git', 'clone', url_git, download_path]
        result = subprocess.run(cmd, check=True)
        print(f"Repository cloned successfully: {result}")
    process = subprocess.Popen(['git', 'checkout', sha], cwd = download_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    size = judge_folder_if_smaller_than_1gb(download_path)
    if process.returncode == 0:
        return size
    else:
        print(err.decode())
        return size

def judge_folder_if_smaller_than_1gb(folder_path):
    folder_size = get_folder_size(folder_path)
    size_in_gb = folder_size / (1024**3)
    if size_in_gb < 1:
        print(f"Deleting folder {folder_path} as it is smaller than 1GB.")
        return 1
    else:
        print(f"Keeping folder {folder_path} as it is larger than or equal to 1GB.")
        return 0



def delete_folder_if_smaller_than_1gb(folder_path):
    folder_size = get_folder_size(folder_path)
    size_in_gb = folder_size / (1024**3)
    if size_in_gb < 1:
        print(f"Deleting folder {folder_path} as it is smaller than 1GB.")
        shutil.rmtree(folder_path)
    else:
        print(f"Keeping folder {folder_path} as it is larger than or equal to 1GB.")



def repo_size(url):
    parsed_url = urlparse(url)
    path_parts = parsed_url.path.strip("/").split("/")
    repo_name = path_parts[1]
    path = 'repos/' + repo_name
    if os.path.exists(path):
        delete_folder_if_smaller_than_1gb(path)


def joern_analyze_code(joern_cli_path, cpg_file_path, joern_script_path):
    cmd = [
        joern_cli_path,
        "--script", joern_script_path,
    ]
    
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    
    if result.returncode == 0:
        print(result.stdout)
        return 1
    else:
        print(result.stderr)
        return 0


def call_analyze(query_path, function, rep):
    text = """
import io.shiftleft.codepropertygraph.generated._
import overflowdb.traversal._
import java.io.File
import java.io.PrintWriter

importCode(inputPath="path/{repo}", projectName="{repo}")
   
val calls = cpg.call("{func}")
val file_call = calls.method.file.toJsonPretty
val callsToRewindnew = cpg.call("{func}")
val callersJson = callsToRewindnew.toJsonPretty
val outputPathfile = "path{func}_file_output.json"
val outputPathfunc = "path{func}_func_output.json"
val writer = new PrintWriter(new File(outputPathfile))
writer.write(file_call)
writer.close()
val writer1 = new PrintWriter(new File(outputPathfunc))
writer1.write(callersJson)
writer1.close()
""".format(func=function, repo = rep)
    with open(query_path, 'w') as file:
        file.write(text)
    joern_cli_path = "your_path"
    cpg_file_path = "your_path/{repo}/cpg.bin".format(repo = rep)
    joern_script_path = query_path
    success = joern_analyze_code( joern_cli_path, cpg_file_path, joern_script_path)
    return success


def patch_context(f_file, f_line, function, repo):
    with open (f_file, 'r')as f1:
        file_data = json.load(f1)
        files = []
        for file in file_data:
            files.append(file['name'])

    with open (f_line, 'r')as f2:
        file_line = json.load(f2)
        lines = []
        for line in file_line:
            lines.append(line['lineNumber'])
    calls = {}
    calls['func'] = function
    calls['call'] = [{}] * len(files)
    for count in range(len(files)):
        calls['call'][count] = {}
        calls['call'][count]['file'] = files[count]
        calls['call'][count]['line'] = lines[count]
        calls['call'].append(calls['call'][count])
    context = []
    for count in range(len(calls['call'])):
        path = 'repos/' + repo + '/' + calls['call'][count]['file']
        Language.build_library(
            'build/my-languages.so',
            [
                'tree-sitter/vendor/tree-sitter-cpp'
            ]
        )
        CPP_LANGUAGE = Language('build/my-languages.so', 'cpp')
        parser = Parser()
        parser.set_language(CPP_LANGUAGE)
        extension = path.split('.')[-1]
        c_extensions = ['c', 'cpp', 'cc', 'h', 'cxx', 'c++', 'hh']
        if extension in c_extensions:
            with open(path, 'r', errors='ignore') as file:
                lines = file.read()
            code = lines
            tree = parser.parse(bytes(code,"utf-8"))
            root_node = tree.root_node
            code = code.split("\n")
            for child_node in root_node.children:
                if child_node.type == "function_definition":
                    function_start_line = child_node.start_point[0]
                    function_end_line = child_node.end_point[0]
                
                    if function_start_line != function_end_line:
                        function_code = code[function_start_line:function_end_line + 1]
                        
                        function_code = "\n".join(function_code)
                        if (function_start_line < calls['call'][count]['line'] < function_end_line + 1):
                            print("Find!!!!", function_start_line, function_end_line + 1)
                            code_new = code[calls['call'][count]['line'] - 3:calls['call'][count]['line'] + 10]
                            code_new = "\n".join(code_new)
                            context.append(code_new)
                    else:
                        function_code = code[function_start_line]

        else:
            context.append(None)
    return context


def count_tokens(source_code):
    token_count = 0
    for token in tokenize.generate_tokens(io.StringIO(source_code).readline):
        token_count += 1
    return token_count 

def all_process(repo_url):
    api_url, rep = get_commit_link(repo_url)
    commit = get_commit_information(api_url, rep)
    description_pro = description_update(commit, rep)
    if len(commit['files']) > 1:
        flag = 2
        
        flag, new_patches = patch_classify(commit)
        if flag == 0:
            print("----None!!!")
        elif flag == 1:
            print("----One!!!")
        elif flag == 2:
            print("----Some!!!")
        commit['files'] = new_patches
    else:
        flag = 1
        print("----One!!!")

    patch_func = []
    patch_new = []
    impact_answer = []
    for i in range(len(commit['files'])):
        patch_infor = {}
        func_tokens = 0
        patch_tokens = 0
        if commit['files'][i]['raw_url'] != None:
            new_url = get_download_url(commit['files'][i]['raw_url'], commit['parents_sha'])
            filename = os.path.basename(commit['files'][i]['filename'])
            directory_path = 'result/'+ rep.REPO
            if not os.path.exists(directory_path):
                os.makedirs(directory_path)
            save_path = 'result/'+ rep.REPO + '/' + filename
            extension = filename.split('.')[-1]
            c_extensions = ['c', 'cpp', 'cc', 'h', 'cxx', 'c++', 'hh']
            if extension in c_extensions:
                file_download(new_url, save_path)
                if 'patch' in commit['files'][i]:
                    lines = get_line(commit['files'][i]['patch'])
                    patch_infor['filename'] = commit['files'][i]['filename']
                    patch_infor['save_path'] = save_path
                    patch_infor['patch'] = commit['files'][i]['patch']
                    patch_infor['modify_locate'] = lines
                    patch_infor['funcs'] = []
                    patch_infor['func_name'] = []
                    patch_tokens = patch_tokens + 0.3 * len(commit['files'][i]['patch'])
                    patch_new.append(patch_infor['patch'])
                    for j in range(len(lines)):
                        line = lines[j]
                        if os.path.exists(save_path):
                            func, func_name = get_func(save_path, line)
                            patch_infor['funcs'].append(func)
                            func_tokens = func_tokens + 0.3 * len(func)
                            patch_infor['func_name'].append(func_name)
                    patch_func.append(patch_infor)
                    if flag == 1 or flag == 2:
                        
                        
                        tokens = func_tokens + patch_tokens
                        if tokens < 100000:
                            answer = LLM_impact(description_pro, patch_infor['patch'], patch_infor['funcs'])
                            impact_answer.append(answer)
                        elif tokens > 100000:
                            patch_infor['funcs'] = ''
                            answer = LLM_impact(description_pro, patch_infor['patch'], patch_infor['funcs'])
                            impact_answer.append(answer)

    if len(impact_answer) > 0:
        for i in range(len(impact_answer)):
            if impact_answer[i]['answer'] == 1:
                flag_impact = 1
                
            else:
                flag_impact = 0
                funcs = len(patch_func[i]['func_name'])
                function_name_new = []
                
                for j in range(funcs):
                    function_name_new.append(patch_func[i]['func_name'][j])
                function_name = list(set(function_name_new))
                break
        if flag_impact == 1:
            patch_new = []
            functions = []
            patch_tokens = 0
            for i in range(len(commit['files'])):
                patch_new.append(commit['files'][i]['patch'])
                patch_token = 0.3 * len(commit['files'][i]['patch'])
                patch_tokens =  patch_tokens + patch_token
            func_tokens = 0
            for i in range(len(patch_func)):
                for j in range(len(patch_func[i]['funcs'])):
                    if patch_func[i]['funcs'][j] != 'NULL':
                        functions.append(patch_func[i]['funcs'][j])
                        func_token = 0.3 * len(patch_func[i]['funcs'][j])
                        func_tokens = func_tokens + func_token
            tokens = patch_tokens + func_tokens
            if tokens < 100000:
                analyze_answer = LLM_analyze_without_joern(description_pro, patch_new, functions)
                
            else:
                functions = ''
                analyze_answer = LLM_analyze_without_joern(description_pro, patch_new, functions)
                
            return analyze_answer
        if flag_impact == 0:
            git_url = url_change(repo_url)
            repo = get_repo(repo_url)
            context_tokens = 0
            size = repo_download(git_url, repo, commit['parents_sha'])
            if size == 1:
                query_path = "calls_query.sc" 
                context = {}
                patch_tokens = 0
                for i in range(len(commit['files'])):
                    patch_new.append(commit['files'][i]['patch'])
                    patch_token = 0.3 * len(commit['files'][i]['patch'])
                    patch_tokens =  patch_tokens + patch_token
                for i in range(len(function_name)):
                    name = function_name[i]
                    if name != 'NULL':
                        
                        success = call_analyze(query_path, name, rep.REPO)
                        if success == 1:
                            f_file = 'path'+ name + '_file_output.json'
                            f_line = 'path'+ name + '_func_output.json'
                            context[name] = patch_context(f_file, f_line, name, rep.REPO)

                        elif success == 0:
                            context[name] = 'NULL'
                            
                    else:
                        context[name] = 'NULL'
                    context_tokens = context_tokens + 0.3 * len(context[name])
                tokens = patch_tokens + context_tokens
                if tokens < 100000:
                    analyze_answer = LLM_analyze(description_pro, patch_new, context)
                    return analyze_answer
                else:
                    context = ''
                    analyze_answer = LLM_analyze(description_pro, patch_new, context)
                    return analyze_answer

            elif size == 0:
                functions = []
                func_tokens = 0
                for i in range(len(patch_func)):
                    for j in range(len(patch_func[i]['funcs'])):
                        if patch_func[i]['funcs'][j] != 'NULL':
                            functions.append(patch_func[i]['funcs'][j])
                            func_token = 0.3 * len(patch_func[i]['funcs'][j])
                            func_tokens = func_tokens + func_token
                if func_tokens < 100000:
                    analyze_answer = LLM_analyze_without_joern(description_pro, patch_new, functions)
                else:
                    functions = ''
                    analyze_answer = LLM_analyze_without_joern(description_pro, patch_new, functions)
                return analyze_answer
            
    elif len(impact_answer) == 0:
        git_url = url_change(repo_url)
        repo = get_repo(repo_url)
        repo_download(git_url, repo, commit['parents_sha'])
        size = repo_download(git_url, repo, commit['parents_sha'])
        context_tokens = 0
        if size == 1:
            query_path = "calls_query.sc" 
            context = {}
            function_name_new = []
            patch_tokens = 0
            for i in range(len(commit['files'])):
                if 'patch' in commit['files'][i]:
                    patch_new.append(commit['files'][i]['patch'])
                    patch_token = 0.3 * len(commit['files'][i]['patch'])
                    patch_tokens =  patch_tokens + patch_token
            for i in range(len(patch_func)):
                for j in range(len(patch_func[i]['func_name'])):
                    function_name_new.append(patch_func[i]['func_name'][j])
            for i in range(len(function_name_new)):
                name = function_name_new[i]
                if name != 'NULL':
                    success = call_analyze(query_path, name, rep.REPO)
                    if success == 1:
                        f_file = 'path'+ name + '_file_output.json'
                        f_line = 'path'+ name + '_func_output.json'
                        context[name] = patch_context(f_file, f_line, name, rep.REPO)
                        context_tokens = context_tokens + 0.3 * len(context[name])
                    elif success == 0:
                        context[name] = 'NULL'
                else:
                    context[name] = 'NULL'
            tokens = patch_tokens + context_tokens
            if tokens < 100000:
                analyze_answer = LLM_analyze(description_pro, patch_new, context)
                return analyze_answer
            else:
                context = ''
                analyze_answer = LLM_analyze(description_pro, patch_new, context)
                return analyze_answer
        elif size == 0:
            functions = []
            func_tokens = 0
            for i in range(len(patch_func)):
                    for j in range(len(patch_func[i]['funcs'])):
                        if patch_func[i]['funcs'][j] != 'NULL':
                            functions.append(patch_func[i]['funcs'][j])
                            func_token = 0.3 * len(patch_func[i]['funcs'][j])
                            func_tokens = func_tokens + func_token
            if func_tokens < 100000:
                analyze_answer = LLM_analyze_without_joern(description_pro, patch_new, functions)
            else:
                functions = ''
                analyze_answer = LLM_analyze_without_joern(description_pro, patch_new, functions)
            return analyze_answer
    

def get_folder_size(folder_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if not fp.startswith(os.path.join(dirpath, '.git')):
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
    return total_size


url_list = []
lines = 0
datasets_path = 'path.txt'
with open(datasets_path, 'r') as datasetsfile:
    content = datasetsfile.read()
    urls = content.strip().split('\n')
    for url in urls:
        url_list.append(url)
        lines = lines + 1
with open ('checkpoint.txt', 'r') as file:
    content = file.read
    line = file.readline()
    number = int(line.strip())

if content == '':
    read_line = 0
else:
    read_line = number

result_path = 'result_path'
temporary_path = 'result_trace_path'
checkpoint = number
with open(result_path, 'a') as outputfile:
    results = []
    for i in range(number, len(url_list)):
        result = {}
        url = url_list[i]
        result['url'] = url
        last_result = all_process(url)
        result['result'] = last_result
        with open(temporary_path, 'a') as f:
             json.dump(result, f, indent=4)
             f.write('\n')
        results.append(result)
        # repo_size(url)
        checkpoint = checkpoint + 1
        print("*********Now number is ", checkpoint, "*********")
        with open ('checkpoint.txt', 'w') as file:
            file.write(str(checkpoint))
    json.dump(results, outputfile, indent=4)


