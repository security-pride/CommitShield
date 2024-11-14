
import requests
import json
import os
import subprocess
import re
import random
import shutil
from git import Repo
from openai import OpenAI
from urllib.parse import urlparse
from datetime import datetime
from collections import Counter
from tree_sitter import Language, Parser
token = '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'
def run_git_command(command, repo_path):
    try:
        # 使用subprocess.run来执行命令，并捕获输出
        # 
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True, encoding='utf-8', cwd='repos' + f'{repo_path}')
        if result.returncode == 0:
            return result.stdout
        else:
            raise Exception(f"Error running git command: {result.stderr}")
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    
def get_commit(filepath, repo, sha):
    path = repo
    start_date = "2024-01-01"
    end_date = "2024-12-31"
    try:
        result = subprocess.run(['git', 'log', '--follow', '--pretty=format:%H', filepath], 
                                check=True,  # 如果命令失败，则抛出异常
                                stdout=subprocess.PIPE,  # 捕获标准输出
                                stderr=subprocess.PIPE,  # 捕获错误输出
                                text=True,
                                encoding='utf-8',
                                cwd='../repos/'+ f'{path}')  # 将输出解码为文本
        # 打印所有commit
        return result.stdout
    except subprocess.CalledProcessError as e:
        # 打印错误信息
        print(f"An error occurred while running git log: {e.stderr}")

def get_repo(url):
    parsed_url = urlparse(url)
    repo_path = parsed_url.path.lstrip('/')
    parts = repo_path.split('/')
    repo_field = parts[1]
    return repo_field

def get_file_history(repo_path, file_path):
    # 构建git log命令，使用--follow来追踪文件历史
    os.chdir(repo_path)
    command = f"git log --follow {file_path}"
    # 运行命令并获取输出
    history = run_git_command(command, repo_path)
    return history

def get_commit_information(repo_url):
    url = repo_url.replace("github.com", "api.github.com/repos").replace("commit", "commits")
    response = requests.get(url, headers={'Authorization': f'token {token}'})
    if response.status_code == 200:
    # 解析响应内容
        commit_info = response.json()
        commit = {}
        commit['sha'] = commit_info['sha']
        commit['message'] = commit_info['commit']['message']
        commit['url'] = commit_info['url']
        commit['status'] = commit_info['stats']
        commit['files'] = commit_info['files']
        print(len(commit_info['files']))
        if len(commit_info['parents']) == 1:
            commit['parents_commit'] = commit_info['parents'][0]['url']
            commit['parents_sha'] = commit_info['parents'][0]['sha']
        commit['comments_url'] = commit_info['comments_url']
        return commit
    # 打印提交信息
    else:
        print("Failed to get commit information:", response.status_code)
        return None
    
def vul_intro_check(commit_infor):
    # 提取rep和commit id
    commit_id = commit_infor['sha']
    commit_files = commit_infor['files']
    files = []
    for i in range(len(commit_infor['files'])):
        commit_file_path = commit_infor['files'][i]['filename']
        files.append(commit_file_path)
    return files

def LLM_vulfix(description, patch):
    client = OpenAI(
        api_key="sk-239f93840dd34ca9b895f2a8632153f2",
        base_url="https://api.deepseek.com",
    )
    system_prompt = """
    You are a patch analysis expert. Please determine whether the patch is related to vulnerability fixes based on its description and content. Please note that this patch may be related to the description, but not to the vulnerability repair. If you are certain that it is related to the vulnerability repair, please output 1. If it is not related to the vulnerability repair, please output 0.
    Please output in JSON format.The content of the target JSON file is as follows:
    EXAMPLE JSON OUTPUT:
    {
        "output":
    """

    user_prompt = """I will provide you with the following information:
    1.commit message: {describe}
    2.one patch of this commit: {patch_i} 
    Please determine whether the patch is related to the vulnerability fix mentioned in the description based on this information. If the description mentions the content of the patch but it is not a vulnerability fix, please consider it irrelevant.
    """.format(describe = description, patch_i = patch)

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

def LLM_analyze(del_lines, patch, add_lines, patch_last, funcs):
    client = OpenAI(
        api_key="sk-239f93840dd34ca9b895f2a8632153f2",
        base_url="https://api.deepseek.com",
    )
    system_prompt = """
    You are a Vulnerability Import Detection Specialist who specialises in identifying vulnerability imports based on patch differences. Your role is to determine if a vulnerability in a vulnerability fix commit is caused by a patch in another commit, based on information provided by the user. A vulnerability can be considered introduced if a line of code that was removed in a vulnerability patch was added or modified in a historical patch submission. If the vulnerability was introduced by a historically submitted vulnerability patch, output '1'; otherwise output '0'.    Please output in JSON format.The content of the target JSON file is as follows:
    EXAMPLE JSON OUTPUT:
    {
        "output": "1/0"
    }
    """
    
    user_prompt = """
    You are given the following details for analysis:
    1.Patch for vulnerability fix: {vulfix_patch}
    2.Code lines deleted in vulnerability fix patch: {bug_lines}
    3.Patch for a historical commit: {patch_before}
    Task:
    If the deleted line of code appears in a history commit of a patch, that history commit is likely to introduce a vulnerability caused by the deleted line of code.    Please output in JSON format.
    """.format(vulfix_patch = patch, bug_lines = del_lines, patch_before = patch_last, bug_lines_intro = add_lines, functions = funcs)
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
    responses = response.choices[0].message.content
    data_json = json.loads(responses)
    return data_json

def url_change(url):
    match = re.search(r'github\.com[:/](.+?)/commit', url)
    if match:
        repo_path = match.group(1)
        return f"https://github.com/{repo_path}.git"
    else:
        raise ValueError("Invalid GitHub commit URL")

def get_folder_size(folder_path):
    total_size = 0
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            # 跳过Git目录，因为它们通常包含二进制文件和可能不需要计算的大小
            if not fp.startswith(os.path.join(dirpath, '.git')):
                if os.path.exists(fp):
                    total_size += os.path.getsize(fp)
    return total_size
def delete_folder_if_smaller_than_1gb(folder_path):
    folder_size = get_folder_size(folder_path)
    # 将大小转换为GB，1GB = 1024**3 bytes
    size_in_gb = folder_size / (1024**3)
    if size_in_gb < 1:
        print(f"Deleting folder {folder_path} as it is smaller than 1GB.")
        if os.path.exists(folder_path):
            # 使用rmdir命令递归删除目录
            try:
                # 在Windows中，使用 /S 选项来递归删除目录
                subprocess.run(['rmdir', '/S', '/Q', folder_path], check=True)
                print(f" {folder_path}  deleted")
            except subprocess.CalledProcessError as e:
                print(f"Delete failed：{e}")
        else:
            print(f" {rep_path} not exists")
    else:
        print(f"Keeping folder {folder_path} as it is larger than or equal to 1GB.")

def get_add_lines(patch):
    add_lines = [line[1:].strip() for line in patch.split('\n') if line.startswith('-')]
    if len(add_lines) == 0:
        add_lines = [line[1:].strip() for line in patch.split('\n') if line.startswith('+')]
    return add_lines
def file_download(url, save_path):
    headers = {
        "Authorization": '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'  # 替换为你的令牌
    }
    try:
        # 发送 GET 请求
        response = requests.get(url, headers=headers)

        # 检查响应状态码
        if response.status_code == 200:
            # 打开文件并写入内容
            with open(save_path, 'wb') as file:
                file.write(response.content)
            print(f"Download successfully: {save_path}")
        else:
            print(f"Download failed, status: {response.status_code}")
    except Exception as e:
        print(f"ERROR: {e}")

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

def get_func(file_path, line_number):
    Language.build_library(
        'build/my-languages.so',
        [
            'tree-sitter/tree-sitter-cpp'
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
            # 不在同一行
            if function_start_line != function_end_line:
                function_code = code[function_start_line:function_end_line + 1]
                
                function_code = "\n".join(function_code)
                if (function_start_line < line_number < function_end_line + 1):
                    print("Find!!!!", function_start_line, function_end_line + 1)
                    function_name_line = code[function_start_line]
                    # match = re.search(r'^(.*?\s)([^\(]+)', function_name_line, re.MULTILINE)
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
                        function_code = code[line_number -20:line_number + 20]
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
                        function_code = code[line_number -20:line_number + 20]
                        return function_code,function_name

            else:
                function_code = code[function_start_line]
                function_name = 'NULL'
                return function_code,function_name
            
        elif child_node.type != "function_definition":
            for child in child_node.children:
                function_code, function_name = find_function_define(child, code, line_number)
                if function_name != 'NULL' and function_code != 'NULL':
                    function_code = code[line_number -20:line_number + 20]
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
        # 不在同一行

        if function_start_line != function_end_line:
            function_code = code[function_start_line:function_end_line + 1]
            
            function_code = "\n".join(function_code)
            if (function_start_line < line_number < function_end_line + 1):
                print("Find!!!!", function_start_line, function_end_line + 1)
                function_name_line = code[function_start_line]
                # match = re.search(r'^(.*?\s)([^\(]+)', function_name_line, re.MULTILINE)
                print(function_name_line)
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


def get_functions(commit):
    new_url = commit['raw_url']
    filename = os.path.basename(commit['filename'])
    directory_path = 'result'
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
    save_path = 'result/'+ '/' + filename
    file_download(new_url, save_path)
    lines = get_line(commit['patch'])
    funcs = []
    for j in range(len(lines)):
        line = lines[j]
        if os.path.exists(save_path):
            func, func_name = get_func(save_path, line)
            funcs.append(func)

    return funcs


'''with open('bugfix_commits_all.json', 'r', encoding='utf-8') as file, open (vul_intro_path, 'w') as f:
    data = json.load(file)
    
    vul_intros = []
    for part in data:
        vul_intro = {}
        if part['language'][0] == 'c' or part['language'][0] == 'cpp':
            vul_intro['fix_commit'] = 'https://github.com/' + part['repo_name'] + '/commit/' + part['fix_commit_hash']
            vul_intro['bug_commit'] = 'https://github.com/' + part['repo_name'] + '/commit/' + part['bug_commit_hash'][0]
            vul_intros.append(vul_intro)
    json.dump(vul_intros, f, indent=4)'''
            



vul_intro_path = 'not_first.json'
url_list = []
bug_list = []
lines = 0
with open(vul_intro_path, 'r', encoding= 'utf-8') as file:
    data = json.load(file)
    for part in data:
        url_list.append(part['fix_commit'])
        bug_list.append(part['bug_commit'])

with open ('checkpoint.txt', 'r') as file:
    content = file.read
    line = file.readline()
    number = int(line.strip())

with open ('match_number.txt', 'r') as file:
    content = file.read
    line = file.readline()
    match_number1 = int(line.strip())

repo_path = '../repos'
checkpoint = number
match_number = match_number1
dataset = []
for i in range(number, len(url_list)):
    bug_url = bug_list[i]
    
    
    rep = get_repo(url_list[i])
    api_url = url_list[i].replace("github.com", "api.github.com/repos").split("/commit/")[0]
   
    patch_1 = []
    del_lines = []
    flag = 0
    match_flag = 0
    response = requests.get(api_url)
    if response.status_code == 200:
        # 请求成功，解析响应内容
        repo_data = response.json()
        repo_size = repo_data.get('size', '未知')
        if repo_size/(1024*1024) < 1:
            size_flag = 1
        else:
            size_flag = 1
        print(f"Repo size:{repo_size} KB")
    else:
        # 请求失败，打印错误信息
        print(f"Request failed, status:{response.status_code}")
        size_flag = 0
    if size_flag == 1:
        rep_path = '../repos/' + rep
        tokens = 0
        commit_infor = get_commit_information(url_list[i])
        if commit_infor != None:
        #print(commit_infor['files'])
            patch_tokens = 0
            del_lines_tokens = 0
            if commit_infor != 0:
                sha = commit_infor['sha']
                message = commit_infor['message']
                files_path = vul_intro_check(commit_infor)  # 你想要追溯的文件的相对路径
                if not os.path.exists(rep_path):
                    download_url = url_change(url_list[i])
                    clone_command = f'git clone {download_url} {rep_path}'
                    try:
                        subprocess.check_call(clone_command, shell=True)
                    except subprocess.CalledProcessError as e:
                        print(f'{e}')
                process = subprocess.Popen(['git', 'checkout', sha], cwd = rep_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = process.communicate()
                if process.returncode == 0:
                    flag_commit = 1
                else:
                    print(err.decode())
                    flag_commit = 0
                if flag_commit == 1:
                    if len(files_path) == 1:
                        result = get_commit(files_path[0], rep, sha)
                        patch_tokens = patch_tokens + 0.3*len(commit_infor['files'][0]['patch'])
                        del_lines = [line[1:] for line in commit_infor['files'][0]['patch'].split('\n') if line.startswith('-')]
                        if len(del_lines) == 0:
                            del_lines = [line[1:] for line in commit_infor['files'][0]['patch'].split('\n') if line.startswith('+')]
                        patch_one = commit_infor['files'][0]['patch']

                        shas = result.splitlines()
                    elif len(files_path) > 1:
                        result = []
                        files_path_new = []
                        files_new = []
                        answer_x = 0
                        for num in range(len(commit_infor['files'])):
                            if 'test' not in commit_infor['files'][num]['filename']:
                                if 'patch' in commit_infor['files'][num]:
                                    answer = LLM_vulfix(commit_infor['message'], commit_infor['files'][num]['patch'])
                                    answer_x = answer['output']
                                    if answer['output'] == 1:
                                        files_path_new.append(commit_infor['files'][num]['filename'])
                                        files_new.append(commit_infor['files'][num])
                                        patch_tokens = patch_tokens + 0.3*len(commit_infor['files'][num]['patch'])
                        if answer_x == 0:
                            files_new = commit_infor['files']
                            files_path_new = files_path
                        
                        for m in range(len(files_new)):
                            if 'test' not in files_path_new[m]:
                                if 'patch' in files_new[m]:
                                    patch = files_new[m]['patch']
                                    #deleted_lines = [line for line in commit_infor['files'][0]['patch']('\n') if line.startswith('-')]
                                    del_lines = [line[1:] for line in files_new[m]['patch'].split('\n') if line.startswith('-')]
                                    # del_lines = [line for line in files_new[m]['patch'].split('\n') if line.startswith('-')]
                                    for num in range(len(del_lines)):
                                        del_lines_tokens = del_lines_tokens + 0.3*len(del_lines[num])
                
                                    del_lines.append(del_lines)
                                    patch_1.append(patch)
                        if len(files_new) == 1:
                            result = get_commit(files_path_new[0], rep, sha)
                            patch_one = files_new[0]['patch']
                            shas = result.splitlines()
                        elif len(files_new) > 1:
                            files_path = files_path_new
                            for num in range(len(files_path)):
                                result_i = get_commit(files_path[num], rep, sha)
                                sha_i = result_i.splitlines()
                                result.append(sha_i)
                            #common_urls = set(result[0])
                            common_elements = set.intersection(*map(set, result))
                            merged_list = []
                            for lst in result:
                                for item in lst:
                                    if item not in merged_list or item in common_elements:
                                        merged_list.append(item)
                            shas = merged_list
                    
                    new_bug_url = url_list[i].replace(commit_infor['sha'], shas[1])
                    '''if new_bug_url == bug_url:
                        print()
                        data = {}
                        data['url'] = url_list[i]
                        dataset.append(data)'''
                        
                    start = 1
                    patch_last_tokens = 0
                    add_lines_tokens = 0
                    flag_number = 0
                    no_match = 0
                    check_num = 0
                    flag_check = 0
                    for j in range(start, len(shas)):
                        new_url = url_list[i].replace(commit_infor['sha'], shas[j])
                        commit_infor_last = get_commit_information(new_url)
                        result = {}
                        result['vul_url'] = url_list[i]
                        
                        if len(files_path) == 1:
                            for k in range(len(commit_infor_last['files'])):
                                if commit_infor_last['files'][k]['filename'] == files_path[0]:
                                    if 'patch' in commit_infor_last['files'][k]:
                                        # funcs = get_functions(commit_infor_last['files'][k])
                                        patch_last = commit_infor_last['files'][k]['patch']
                                        patch_last_tokens = patch_last_tokens + 0.3*len(patch_last)
                                        add_lines = get_add_lines(patch_last)
                                        for num in range(len(add_lines)):
                                            add_lines_tokens = add_lines_tokens + 0.3*len(add_lines[num])
                                        tokens = patch_tokens + del_lines_tokens + add_lines_tokens + patch_last_tokens
                                        if tokens > 120000:
                                            add_lines = 'NULL'
                                        funcs = ''
                                        llm_result = LLM_analyze(del_lines, patch_one, add_lines, patch_last, funcs)
                                        if llm_result['output'] == '1':
                                            flag = 1
                                            flag_check = 1
                                            flag_number = flag_number + 1
                                            result['vul_intro_url'] = new_url
                                            result['result'] = llm_result
                                            match_number = match_number + 1
                                            
                                            if new_url == bug_url:
                                                result['match'] = 'match'
                                                match_flag = 1
                                               
                                            else:
                                                no_match = no_match + 1
                                                result['match'] = 'not match'
                                               
                                            break
                                            
                                        else:
                                            no_match = no_match + 1
                                            flag = 0
                            
                        elif len(files_path) > 1:
                            patch_last = []
                            add_lines = []
                            
                            '''if len(commit_infor_last['files']) == 1:
                                if commit_infor_last['files'][0]['filename'] == files_path[number]:
                                    patch_last.append(commit_infor_last['files'][0]['patch'])
                                    patch_last_tokens = patch_last_tokens + 0.3*len(patch_last)
                                    add_line = get_add_lines(commit_infor_last['files'][0]['patch'])
                                    for num in range(len(add_line)):
                                        add_lines_tokens = add_lines_tokens + 0.3*len(add_line[num])
                                    add_lines.append(get_add_lines(commit_infor_last['files'][0]['patch']))
                                    patch_1 = files_new[num]['patch']'''
                        
                               # elif len(commit_infor_last['files']) > 1:
                            for number in range(len(files_path)):
                                for k in range(len(commit_infor_last['files'])):
                                    if 'patch' in commit_infor_last['files'][k]:
                                        if commit_infor_last['files'][k]['filename'] == files_path[number]:
                                            patch_last.append(commit_infor_last['files'][k]['patch'])
                                            patch_last_tokens = patch_last_tokens + 0.3*len(patch_last)
                                            add_line = get_add_lines(commit_infor_last['files'][k]['patch'])
                                            for num in range(len(add_line)):
                                                add_lines_tokens = add_lines_tokens + 0.3*len(add_line[num])
                                            add_lines.append(get_add_lines(commit_infor_last['files'][k]['patch']))
                                    
                            tokens = patch_tokens + del_lines_tokens + add_lines_tokens + patch_last_tokens
                            #print(tokens, patch_tokens, del_lines_tokens, add_lines_tokens, patch_last_tokens)
                            if tokens > 120000:
                                add_lines = 'NULL'
                            funcs = ''
                            llm_result = LLM_analyze(del_lines, patch_1, add_lines, patch_last, funcs)
                            
                            if llm_result['output'] == '1':
                                flag = 1
                                match_number = match_number + 1 
                                flag_number = flag_number + 1
                                result['vul_intro_url'] = new_url
                                result['result'] = llm_result
                                
                                if new_url == bug_url:
                                    result['match'] = 'match'
                                    match_flag = 1
                                    
                                else:
                                    result['match'] = 'not match'
                                    
                                    no_match = no_match + 1
                                break
                            else:
                                flag = 0
                                no_match = no_match + 1
                        if no_match > 30:
                            flag = 0
                            break
                            

                        if flag == 1:
                            if match_flag == 1:
                                with open ('path.json', 'a') as file:
                                    result['match'] = 'match'
                                    result['match_number'] = flag_number -1
                                    json.dump(result, file, indent=4)
                                    file.write('\n')
                                break
                            else:
                                result['match'] = 'not match'
                                    
                        '''if flag_number > 4:
                            flag = 0
                            break'''
                        if flag_check == 1:
                            check_num = check_num +1
                        if check_num >= 10:
                            with open ('path.json', 'a') as file:
                                result['match'] = 'not match'
                                result['match_number'] = flag_number
                                json.dump(result, file, indent=4)
                                file.write('\n')
                            break

                    if flag == 0 and flag_check != 1:
                       result = {}
                       potential_url = url_list[i].replace(commit_infor['sha'], shas[1])
                       if bug_url == potential_url:
                            result['vul_url'] = url_list[i]
                            result['vul_intro_url'] = potential_url
                            result['match'] = 'match'
                       else:
                            
                            result['vul_url'] = url_list[i]
                            result['match'] = 'miss'
                       with open ('path.json', 'a') as file:
                            json.dump(result, file, indent=4)
                            file.write('\n')            
    checkpoint = checkpoint + 1
    with open ('checkpoint.txt', 'w') as file, open ('match_number.txt', 'w') as f:
        file.write(str(checkpoint))
        f.write(str(match_number))
       
