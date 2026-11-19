"""Copy an observed trial into output/kgvn with its evidence and exact backups."""

import argparse
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import shutil


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('trial',type=Path)
    parser.add_argument('--audit',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parent.parent
    trial=json.loads((args.trial/'trial.json').read_text(encoding='utf-8'))
    audit=json.loads(args.audit.read_text(encoding='utf-8'))
    if trial['status']!='encrypt_running_observed':
        raise RuntimeError('Only an observed successful encrypted trial can be published.')
    binary=args.trial/trial['mode']/Path(trial['source']).name
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest!=trial['final_device_sha256']:
        raise RuntimeError('Trial checksum is inconsistent.')
    dest=root/'output/kgvn'
    previous=dest/('previous-'+datetime.now(timezone(timedelta(hours=7))).strftime('%Y%m%d-%H%M%S'))
    previous.mkdir(parents=True)
    for name in ('libMyLibName.so','libMyLibName.so.protect3.json','deployment.json'):
        source=dest/name
        if source.exists():
            shutil.copy2(source,previous/name)
    shutil.copy2(binary,dest/'libMyLibName.so')
    metadata=json.loads(Path(str(binary)+'.protect3.json').read_text(encoding='utf-8'))
    metadata['validation'].update(android_device_load='observed_on_bluestacks_android9_arm64_native_bridge',
                                  observed_seconds=trial['trial'][-1]['elapsed'],guard_events=trial['log_analysis']['guard_events'])
    (dest/'libMyLibName.so.protect3.json').write_text(json.dumps(metadata,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    deployment={'package':trial['package'],'status':trial['status'],'tool_version':metadata['version'],
                'installed_path':trial['target'],'serial':trial['serial'],'encrypted_sha256':digest,
                'options':metadata['options'],'observation':trial['log_analysis'],
                'repeat_launches':[{'run':i+1,'observed_seconds':run['samples'][-1]['elapsed'],
                                   'findings':run['analysis']['findings'],
                                   'guard_return_observed':any('event=guard_return' in s for s in run['analysis']['guard_events'])}
                                  for i,run in enumerate(audit['launches'])],
                'environment':audit['interpretation'],'raw_trial':str(args.trial/'trial.json'),
                'audit':str(args.audit),'previous_deployment':str(previous),
                'scope':'Native startup and selected code/data decryption observed; no complete gameplay or general detector validation.'}
    (dest/'deployment.json').write_text(json.dumps(deployment,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print(dest)


if __name__=='__main__':
    main()
