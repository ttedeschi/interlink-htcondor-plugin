from flask import Flask, request
import json
import os
import subprocess
import logging
import yaml
import argparse
import re

parser = argparse.ArgumentParser()

parser.add_argument("--schedd-name", help="Schedd name", type=str, default="")
parser.add_argument("--schedd-host", help="Schedd host", type=str, default="")
parser.add_argument("--collector-host",
                    help="Collector-host", type=str, default="")
parser.add_argument("--cadir", help="CA directory", type=str, default="")
parser.add_argument("--certfile", help="cert file", type=str, default="")
parser.add_argument("--keyfile", help="key file", type=str, default="")
parser.add_argument(
    "--auth-method", help="Default authentication methods", type=str, default=""
)
parser.add_argument("--debug", help="Debug level", type=str, default="")
parser.add_argument(
    "--condor-config", help="Path to condor_config file", type=str, default=""
)
parser.add_argument("--proxy", help="Path to proxy file", type=str, default="")
parser.add_argument(
    "--dummy-job",
    action="store_true",
    help="Whether the job should be a real job or a dummy sleep job",
)
parser.add_argument("--port", help="Server port", type=int, default=8000)

args = parser.parse_args()

if args.schedd_name != "":
    os.environ["_condor_SCHEDD_NAME"] = args.schedd_name
if args.schedd_host != "":
    os.environ["_condor_SCHEDD_HOST"] = args.schedd_host
if args.collector_host != "":
    os.environ["_condor_COLLECTOR_HOST"] = args.collector_host
if args.cadir != "":
    os.environ["_condor_AUTH_SSL_CLIENT_CADIR"] = args.cadir
if args.certfile != "":
    os.environ["_condor_AUTH_SSL_CLIENT_CERTFILE"] = args.certfile
if args.keyfile != "":
    os.environ["_condor_AUTH_SSL_CLIENT_KEYFILE"] = args.keyfile
if args.auth_method != "":
    os.environ["_condor_SEC_DEFAULT_AUTHENTICATION_METHODS"] = args.auth_method
if args.debug != "":
    os.environ["_condor_TOOL_DEBUG"] = args.debug
if args.condor_config != "":
    os.environ["CONDOR_CONFIG"] = args.condor_config
if args.proxy != "":
    os.environ["X509_USER_PROXY"] = args.proxy
if args.proxy != "":
    os.environ["X509_USER_CERT"] = args.proxy
dummy_job = args.dummy_job


global JID
JID = []


def read_yaml_file(file_path):
    with open(file_path, "r") as file:
        try:
            data = yaml.safe_load(file)
            return data
        except yaml.YAMLError as e:
            print("Error reading YAML file:", e)
            return None


global InterLinkConfigInst
interlink_config_path = "./SidecarConfig.yaml"
InterLinkConfigInst = read_yaml_file(interlink_config_path)
print("Interlink configuration info:", InterLinkConfigInst)


def prepare_envs(container):
    env = ["--env"]
    env_data = []
    try:
        for env_var in container.env:
            env_data.append(f"{env_var.name}={env_var.value}")
        env.append(",".join(env_data))
        return env
    except Exception as e:
        logging.info(f"Container has no env specified: {e}")
        return [""]


def prepare_mounts(pod, container_standalone):
    mounts = ["--bind"]
    mount_data = []
    pod_name = (
        container_standalone["name"].split("-")[:6]
        if len(container_standalone["name"].split("-")) > 6
        else container_standalone["name"].split("-")
    )
    pod_name_folder = os.path.join(
        InterLinkConfigInst["DataRootFolder"], "-".join(pod_name[:-1])
    )
    for c in pod["spec"]["containers"]:
        if c["name"] == container_standalone["name"]:
            container = c
    try:
        os.makedirs(pod_name_folder, exist_ok=True)
        logging.info(f"Successfully created folder {pod_name_folder}")
    except Exception as e:
        logging.error(e)
    if "volumeMounts" in container.keys():
        for mount_var in container["volumeMounts"]:
            path = ""
            for vol in pod["spec"]["volumes"]:
                if vol["name"] != mount_var["name"]:
                    continue
                if "configMap" in vol.keys():
                    config_maps_paths = mountConfigMaps(
                        pod, container_standalone)
                    # print("bind as configmap", mount_var["name"], vol["name"])
                    for i, path in enumerate(config_maps_paths):
                        mount_data.append(path)
                elif "secret" in vol.keys():
                    secrets_paths = mountSecrets(pod, container_standalone)
                    # print("bind as secret", mount_var["name"], vol["name"])
                    for i, path in enumerate(secrets_paths):
                        mount_data.append(path)
                elif "emptyDir" in vol.keys():
                    path = mount_empty_dir(container, pod)
                    mount_data.append(path)
                else:
                    # Implement logic for other volume types if required.
                    logging.info(
                        "\n*********\n*To be implemented*\n********"
                    )
    else:
        logging.info("Container has no volume mount")
        return [""]

    path_hardcoded = ""
    mount_data.append(path_hardcoded)
    mounts.append(",".join(mount_data))
    print("mounts are", mounts)
    if mounts[1] == "":
        mounts = [""]
    return mounts


def mountConfigMaps(pod, container_standalone):
    configMapNamePaths = []
    wd = os.getcwd()
    for c in pod["spec"]["containers"]:
        if c["name"] == container_standalone["name"]:
            container = c
    if InterLinkConfigInst["ExportPodData"] and "volumeMounts" in container.keys():
        data_root_folder = InterLinkConfigInst["DataRootFolder"]
        cmd = ["-rf", os.path.join(wd, data_root_folder, "configMaps")]
        shell = subprocess.Popen(
            ["rm"] + cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        _, err = shell.communicate()

        if err:
            logging.error("Unable to delete root folder")

        for mountSpec in container["volumeMounts"]:
            for vol in pod["spec"]["volumes"]:
                if vol["name"] != mountSpec["name"]:
                    continue
                if "configMap" in vol.keys():
                    print("container_standalone:", container_standalone)
                    cfgMaps = container_standalone["configMaps"]
                    for cfgMap in cfgMaps:
                        podConfigMapDir = os.path.join(
                            wd,
                            data_root_folder,
                            f"{pod['metadata']['namespace']}-{pod['metadata']['uid']}/configMaps/",
                            vol["name"],
                        )
                        for key in cfgMap["data"].keys():
                            path = os.path.join(wd, podConfigMapDir, key)
                            path += f":{mountSpec['mountPath']}/{key}"
                            configMapNamePaths.append(path)
                        cmd = ["-p", podConfigMapDir]
                        shell = subprocess.Popen(
                            ["mkdir"] + cmd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        )
                        execReturn, _ = shell.communicate()
                        if execReturn:
                            logging.error(err)
                        else:
                            logging.debug(
                                f"--- Created folder {podConfigMapDir}")
                        logging.debug("--- Writing ConfigMaps files")
                        for k, v in cfgMap["data"].items():
                            full_path = os.path.join(podConfigMapDir, k)
                            with open(full_path, "w") as f:
                                f.write(v)
                            os.chmod(
                                full_path, vol["configMap"]["defaultMode"])
                            logging.debug(
                                f"--- Written ConfigMap file {full_path}")
    return configMapNamePaths


def mountSecrets(pod, container_standalone):
    secret_name_paths = []
    wd = os.getcwd()
    for c in pod["spec"]["containers"]:
        if c["name"] == container_standalone["name"]:
            container = c
    if InterLinkConfigInst["ExportPodData"] and "volumeMounts" in container.keys():
        data_root_folder = InterLinkConfigInst["DataRootFolder"]
        cmd = ["-rf", os.path.join(wd, data_root_folder, "secrets")]
        subprocess.run(["rm"] + cmd, check=True)
        for mountSpec in container["volumeMounts"]:
            for vol in pod["spec"]["volumes"]:
                if vol["name"] != mountSpec["name"]:
                    continue
                if "secret" in vol.keys():
                    secrets = container_standalone["secrets"]
                    for secret in secrets:
                        if secret["metadata"]["name"] != vol["secret"]["secretName"]:
                            continue
                        pod_secret_dir = os.path.join(
                            wd,
                            data_root_folder,
                            f"{pod['metadata']['namespace']}-{pod['metadata']['uid']}/secrets/",
                            vol["name"],
                        )
                        for key in secret["data"]:
                            path = os.path.join(pod_secret_dir, key)
                            path += f":{mountSpec['mountPath']}/{key}"
                            secret_name_paths.append(path)
                        cmd = ["-p", pod_secret_dir]
                        subprocess.run(["mkdir"] + cmd, check=True)
                        logging.debug(f"--- Created folder {pod_secret_dir}")
                        logging.debug("--- Writing Secret files")
                        for k, v in secret["data"].items():
                            full_path = os.path.join(pod_secret_dir, k)
                            with open(full_path, "w") as f:
                                f.write(v)
                            os.chmod(full_path, vol["secret"]["defaultMode"])
                            logging.debug(
                                f"--- Written Secret file {full_path}")
    return secret_name_paths


def mount_empty_dir(container, pod):
    ed_path = None
    if InterLinkConfigInst["ExportPodData"] and "volumeMounts" in container.keys():
        cmd = [
            "-rf", os.path.join(InterLinkConfigInst["DataRootFolder"], "emptyDirs")]
        subprocess.run(["rm"] + cmd, check=True)
        for mount_spec in container["volumeMounts"]:
            pod_volume_spec = None
            for vol in pod["spec"]["volumes"]:
                if vol.name == mount_spec["name"]:
                    pod_volume_spec = vol["volumeSource"]
                    break
            if pod_volume_spec and pod_volume_spec["EmptyDir"]:
                ed_path = os.path.join(
                    InterLinkConfigInst["DataRootFolder"],
                    pod.namespace + "-" +
                    str(pod.uid) + "/emptyDirs/" + vol.name,
                )
                cmd = ["-p", ed_path]
                subprocess.run(["mkdir"] + cmd, check=True)
                ed_path += (
                    ":" + mount_spec["mount_path"] +
                    "/" + mount_spec["name"] + ","
                )

    return ed_path


def parse_string_with_suffix(value_str):
    #should return MB because HTCondor wants MB
    suffixes = {
        "k": 1/10**3,
        "M": 1,
        "G": 10**3,
        "Ki": 1 / 1024,
        "Mi": 1,
        "Gi": 1024,
    }

    match = re.match(r"(\d+)([a-zA-Z]+)", value_str)
    if match:
        numeric_part = match.group(1)
        suffix = match.group(2)
        if suffix in suffixes:
            numeric_value = int(float(numeric_part) * suffixes[suffix])
            return numeric_value
        else:
            return 1
    else:
        print("Unrecognized memory value, setting it to 1 MB")
        return 1


def produce_htcondor_singularity_script(containers, metadata, commands, input_files):
    executable_path = f"./{InterLinkConfigInst['DataRootFolder']}/{metadata['name']}-{metadata['uid']}.sh"
    sub_path = f"./{InterLinkConfigInst['DataRootFolder']}/{metadata['name']}-{metadata['uid']}.jdl"

    requested_cpus = 0
    requested_memory = 0
    for c in containers:
        if "resources" in c.keys():
            if "requests" in c["resources"].keys():
                if "cpu" in c["resources"]["requests"].keys():
                    requested_cpus += int(c["resources"]["requests"]["cpu"])
                if "memory" in c["resources"]["requests"].keys():
                    requested_memory += parse_string_with_suffix(
                        c["resources"]["requests"]["memory"])
    if requested_cpus == 0:
        requested_cpus = 1
    if requested_memory == 0:
        requested_memory = 1

    prefix_ = f"\n{InterLinkConfigInst['CommandPrefix']}"
    try:
        with open(executable_path, "w") as f:
            batch_macros = """#!/bin/bash
"""
            commands_joined = [prefix_]
            for i in range(0, len(commands)):
                commands_joined.append(" ".join(commands[i]))
            f.write(batch_macros + "\n" + "\n".join(commands_joined))

        job = f"""
Executable = {executable_path}
requirements            = (SiteName == "T2_LNL_PD")

Log        = log/mm_mul.$(Cluster).$(Process).log
Output     = out/mm_mul.out.$(Cluster).$(Process)
Error      = err/mm_mul.err.$(Cluster).$(Process)

transfer_input_files = {",".join(input_files)}
should_transfer_files = YES
RequestCpus = {requested_cpus}
RequestMemory = {requested_memory}

when_to_transfer_output = ON_EXIT_OR_EVICT
+MaxWallTimeMins = 60

+WMAgent_AgentName = "whatever"

Queue 1
"""
        #print(job)
        with open(sub_path, "w") as f_:
            f_.write(job)
        os.chmod(executable_path, 0o0777)
    except Exception as e:
        logging.error(f"Unable to prepare the job: {e}")

    return sub_path


def produce_htcondor_host_script(container, metadata):
    executable_path = f"{InterLinkConfigInst['DataRootFolder']}{metadata['name']}-{metadata['uid']}.sh"
    sub_path = f"{InterLinkConfigInst['DataRootFolder']}{metadata['name']}-{metadata['uid']}.jdl"
    try:
        with open(executable_path, "w") as f:
            batch_macros = f"""#!{container['command'][-1]}
""" + "\n".join(
                container["args"][-1].split("; ")
            )

            f.write(batch_macros)

        requested_cpu = container["resources"]["requests"]["cpu"]
        # requested_memory = int(container['resources']['requests']['memory'])/1e6
        requested_memory = container["resources"]["requests"]["memory"]
        job = f"""
Executable = {executable_path}
requirements            = (SiteName == "T2_LNL_PD")

Log        = log/mm_mul.$(Cluster).$(Process).log
Output     = out/mm_mul.out.$(Cluster).$(Process)
Error      = err/mm_mul.err.$(Cluster).$(Process)

should_transfer_files = YES
RequestCpus = {requested_cpu}
RequestMemory = {requested_memory}

when_to_transfer_output = ON_EXIT_OR_EVICT
+MaxWallTimeMins = 60

+WMAgent_AgentName = "whatever"

Queue 1
"""
        #print(job)
        with open(sub_path, "w") as f_:
            f_.write(job)
        os.chmod(executable_path, 0o0777)
    except Exception as e:
        logging.error(f"Unable to prepare the job: {e}")

    return sub_path


def htcondor_batch_submit(job):
    logging.info("Submitting HTCondor job")
    process = os.popen(
        f"condor_submit -pool {args.collector_host} -remote {args.schedd_host} {job} -spool"
    )
    preprocessed = process.read()
    process.close()
    jid = preprocessed.split(" ")[-1].split(".")[0]

    return jid


def delete_pod(pod):
    logging.info(f"Deleting pod {pod['metadata']['name']}")
    with open(
        f"{InterLinkConfigInst['DataRootFolder']}{pod['metadata']['name']}-{pod['metadata']['uid']}.jid"
    ) as f:
        data = f.read()
    jid = int(data.strip())
    process = os.popen(f"condor_rm {jid}")
    preprocessed = process.read()
    process.close()

    os.remove(
        f"{InterLinkConfigInst['DataRootFolder']}{pod['metadata']['name']}-{pod['metadata']['uid']}.jid")
    os.remove(
        f"{InterLinkConfigInst['DataRootFolder']}{pod['metadata']['name']}-{pod['metadata']['uid']}.sh")
    os.remove(
        f"{InterLinkConfigInst['DataRootFolder']}{pod['metadata']['name']}-{pod['metadata']['uid']}.jdl")

    return preprocessed


def handle_jid(jid, pod):
    with open(
        f"{InterLinkConfigInst['DataRootFolder']}{pod['metadata']['name']}-{pod['metadata']['uid']}.jid", "w"
    ) as f:
        f.write(str(jid))
    JID.append({"JID": jid, "pod": pod})
    logging.info(
        f"Job {jid} submitted successfully",
        f"{InterLinkConfigInst['DataRootFolder']}{pod['metadata']['name']}-{pod['metadata']['uid']}.jid",
    )


def SubmitHandler():
    # READ THE REQUEST ###############
    logging.info("HTCondor Sidecar: received Submit call")
    request_data_string = request.data.decode("utf-8")
    print("Decoded", request_data_string)
    req = json.loads(request_data_string)[0]
    if req is None or not isinstance(req, dict):
        logging.error("Invalid request data for submitting")
        #print("Invalid submit request body is: ", req)
        return "Invalid request data for submitting", 400

    # ELABORATE RESPONSE ###########
    pod = req.get("pod", {})
    # print(pod)
    containers_standalone = req.get("container", {})
    # print("Requested pod metadata name is: ", pod["metadata"]["name"])
    metadata = pod.get("metadata", {})
    containers = pod.get("spec", {}).get("containers", [])
    singularity_commands = []

    # NORMAL CASE
    if "host" not in containers[0]["image"]:
        for container in containers:
            logging.info(
                f"Beginning script generation for container {container['name']}"
            )
            commstr1 = ["singularity", "exec"]
            envs = prepare_envs(container)
            image = ""
            mounts = [""]
            singularity_options = metadata.get("annotations", {}).get(
                    "htcondor-job.vk.io/singularity-options", ""
                )
            if containers_standalone is not None:
                for c in containers_standalone:
                    if c["name"] == container["name"]:
                        container_standalone = c
                        mounts = prepare_mounts(pod, container_standalone)
            else:
                mounts = [""]
            #if container["image"].startswith("/") or ".io" in container["image"]:
            if container["image"].startswith("/"):
                image_uri = metadata.get("annotations", {}).get(
                    "htcondor-job.knoc.io/image-root", None
                )
                if image_uri:
                    logging.info(image_uri)
                    image = image_uri + container["image"]
                else:
                    logging.warning(
                        "image-uri not specified for path in remote filesystem"
                    )
            else:
                image = "docker://" + container["image"]
            #image = container["image"]
            logging.info("Appending all commands together...")
            input_files = []
            for mount in mounts[-1].split(","):
                input_files.append(mount.split(":")[0])
            local_mounts = ["--bind", ""]
            for mount in (mounts[-1].split(","))[:-1]:
                local_mounts[1] += (
                    "./"
                    + (mount.split(":")[0]).split("/")[-1]
                    + ":"
                    + mount.split(":")[1]
                    + ","
                )
            if local_mounts[-1] == "":
                local_mounts = [""]

            if "command" in container.keys() and "args" in container.keys():
                singularity_command = (
                    commstr1 
                    + [singularity_options]
                    + envs
                    + local_mounts
                    + [image]
                    + container["command"]
                    + container["args"]
                )
            elif "command" in container.keys():
                singularity_command = (
                    commstr1 + [singularity_options] + envs + local_mounts +
                    [image] + container["command"]
                )
            elif "args" in container.keys():
                singularity_command = (
                    commstr1 + [singularity_options] + envs + local_mounts +
                    [image] + container["args"]
                )
            else:
                singularity_command = commstr1 + envs + local_mounts + [image]
            #print("singularity_command:", singularity_command)
            singularity_commands.append(singularity_command)
        path = produce_htcondor_singularity_script(
            containers, metadata, singularity_commands, input_files
        )

    else:
        #print("host keyword detected, ignoring other containers")
        sitename = containers[0]["image"].split(":")[-1]
        print(sitename)
        path = produce_htcondor_host_script(containers[0], metadata)

    out_jid = htcondor_batch_submit(path)
    #print("Job was submitted with cluster id: ", out_jid)
    handle_jid(out_jid, pod)

    resp = {
            "PodUID": [],
            "PodJID": []
        }

    try:
        with open(
            InterLinkConfigInst["DataRootFolder"] +
            pod["metadata"]["name"] + "-" + pod["metadata"]["uid"] + ".jid",
            "r",
        ) as f:
            f.read()
        resp["PodUID"] = pod["metadata"]["uid"]
        resp["PodJID"] = out_jid
        return json.dumps(resp), 200
    except Exception as e:
        logging.error(f"Unable to read JID from file:{e}")
        return "Something went wrong in job submission", 500


def StopHandler():
    # READ THE REQUEST ######
    logging.info("HTCondor Sidecar: received Stop call")
    request_data_string = request.data.decode("utf-8")
    req = json.loads(request_data_string)
    if req is None or not isinstance(req, dict):
        #print("Invalid delete request body is: ", req)
        logging.error("Invalid request data")
        return "Invalid request data for stopping", 400

    # DELETE JOB RELATED TO REQUEST
    try:
        return_message = delete_pod(req)
        #print(return_message)
        if "All" in return_message:
            return "Requested pod successfully deleted", 200
        else:
            return "Something went wrong when deleting the requested pod", 500
    except Exception as e:
        return f"Something went wrong when deleting the requested pod:{e}", 500


def StatusHandler():
    # READ THE REQUEST #####################
    logging.info("HTCondor Sidecar: received GetStatus call")
    request_data_string = request.data.decode("utf-8")
    #req = json.loads(request_data_string)[0]
    #req = json.loads(request_data_string)
    req_list = json.loads(request_data_string)
    #print("STATUS REQUEST DATA IS THE FOLLOWING:", req)
    if req_list is None or not isinstance(req_list, list):
        #print("Invalid status request body is: ", req)
        logging.error("Invalid request data")
        logging.error(f"STATUS REQUEST DATA IS THE FOLLOWING: {req_list}")
        return "Invalid request data for getting status", 400
    if isinstance(req_list, list):
        if len(req_list) == 0:
            logging.error("Invalid request data")
            logging.error(f"STATUS REQUEST DATA IS THE FOLLOWING: {req_list}")
            if os.path.isfile(args.proxy):
                return "This is a ping request.. I'm alive!", 200
            else:
                return "This is a ping request.. I'm not alive yet, no proxyfile available!", 400
    
    req = req_list[0]

    # ELABORATE RESPONSE #################
    resp = [
        {
            "name": [],
            "UID": [],
            "namespace": [],
            "JID": [],
            "containers": []
        }
    ]
    try:
        with open(
            InterLinkConfigInst["DataRootFolder"] +
            req["metadata"]["name"] + "-" + req['metadata']['uid'] + ".jid",
            "r",
        ) as f:
            jid_job = f.read()
        podname = req["metadata"]["name"]
        podnamespace = req["metadata"]["namespace"]
        poduid = req["metadata"]["uid"]
        resp[0]["name"] = podname
        resp[0]["namespace"] = podnamespace
        resp[0]["UID"] = poduid
        resp[0]["JID"] = jid_job
        process = os.popen(f"condor_q {jid_job} --json")
        preprocessed = process.read()
        process.close()
        job_ = json.loads(preprocessed)
        status = job_[0]["JobStatus"]
        if status == 1:
            state = {"waiting": {
            }
            }
            readiness = False
        elif status == 2:
            state = {"running": {
                "startedAt": "2006-01-02T15:04:05Z",
            }
            }
            readiness = True
        else:
            state = {"terminated": {
                "startedAt": "2006-01-02T15:04:05Z",
                "finishedAt": "2006-01-02T15:04:05Z",
            }
            }
            readiness = False
        for c in req["spec"]["containers"]:
            resp[0]["containers"].append({
                "name": c["name"],
                "state": state,
                "lastState": {},
                "ready": readiness,
                "restartCount": 0,
                "image": "NOT IMPLEMENTED",
                "imageID": "NOT IMPLEMENTED"
            })
        #print(json.dumps(resp))
        return json.dumps(resp), 200
    except Exception as e:
        return f"Something went wrong when retrieving pod status: {e}", 500


def LogsHandler():
    logging.info("HTCondor Sidecar: received GetLogs call")
    request_data_string = request.data.decode("utf-8")
    # print(request_data_string)
    req = json.loads(request_data_string)
    if req is None or not isinstance(req, dict):
        #print("Invalid logs request body is: ", req)
        logging.error("Invalid request data")
        return "Invalid request data for getting logs", 400

    resp = "NOT IMPLEMENTED"

    return json.dumps(resp), 200


app = Flask(__name__)
app.add_url_rule("/create", view_func=SubmitHandler, methods=["POST"])
app.add_url_rule("/delete", view_func=StopHandler, methods=["POST"])
app.add_url_rule("/status", view_func=StatusHandler, methods=["GET"])
app.add_url_rule("/getLogs", view_func=LogsHandler, methods=["GET"])

if __name__ == "__main__":
    app.run(port=args.port, host="0.0.0.0", debug=True)
