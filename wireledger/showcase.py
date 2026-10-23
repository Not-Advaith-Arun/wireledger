"""Generate a self-contained, offline product showcase from computed sample data."""
import argparse
import html
import json
import os
import re
import sys
from pathlib import Path
import tempfile


def render(config):
    assets=Path(__file__).with_name('ui')
    raw=json.dumps(config,ensure_ascii=True).replace('<','\\u003c').replace('&','\\u0026')
    replacements={'TITLE':html.escape(config['name']+' — Workbench'),
                  'STYLE':assets.joinpath('style.css').read_text(encoding='utf-8'),
                  'DATA':raw,'SCRIPT':assets.joinpath('app.js').read_text(encoding='utf-8')}
    return re.sub(r'__(TITLE|STYLE|DATA|SCRIPT)__',lambda match:replacements[match.group(1)],
                  assets.joinpath('index.html').read_text(encoding='utf-8'))



def arguments(parser):
    parser.add_argument('-o','--output',type=Path,required=True)
    parser.add_argument('--overview',action='store_true',help='Generate the five-project overview; combine with --collection-links for a local collection')
    parser.add_argument('--force',action='store_true',help='Replace an existing regular output; existing user inputs/stores remain outside this workflow')
    parser.add_argument('--collection-links',action='store_true',help='Use sibling project-name.html links; generate all five project files beside index.html before using this option')


def generate(args):
    try:
        output=args.output
        if output.is_symlink() or (output.exists() and not output.is_file()):
            raise ValueError('showcase output must be a regular file, never a symlink')
        if output.exists() and not args.force:
            raise ValueError('showcase output exists; choose a new path or pass --force')
        if not output.parent.is_dir():
            raise ValueError('showcase output directory must already exist')
        config=({'catalog':True,'name':'Project collection','slug':'collection'} if args.overview else sample())
        config['local_collection']=args.collection_links
        document=render(config)
        descriptor,temporary=tempfile.mkstemp(prefix='.'+output.name+'.',suffix='.pending',dir=output.parent)
        try:
            with os.fdopen(descriptor,'w',encoding='utf-8') as stream:
                stream.write(document);stream.flush();os.fsync(stream.fileno())
            if args.force:
                if output.is_symlink():raise ValueError('refusing symlink output')
                os.replace(temporary,output)
            else:os.link(temporary,output)
        finally:Path(temporary).unlink(missing_ok=True)
        print('Showcase saved: '+str(output))
        return 0
    except (ValueError,OSError) as exc:
        print('showcase: '+str(exc),file=sys.stderr)
        return 2


def main(argv=None):
    parser=argparse.ArgumentParser(description="Generate an offline showcase from fictional inputs and actual computed examples; existing user stores remain untouched.")
    arguments(parser)
    return generate(parser.parse_args(argv))

def sample():
    from .lab import demo
    report=demo()
    def state(label,title,description,kind):
        if kind=='observations':
            rows=[{'id':str(i),'title':'Loopback observation '+str(i+1),'subtitle':'localhost, disposable lab','status':'TLS verified','tone':'good','detail':'A real loopback TLS handshake was verified against the disposable lab CA, then signed into the witness history.'} for i in range(report['observations'])]
        else:
            rows=[{'id':key,'title':{'content_tampering':'Changed observation bytes','tail_truncation_with_checkpoint':'History truncated to an old prefix'}[key],'subtitle':'Controlled evidence manipulation','status':'Detected' if detected else 'Not detected','tone':'good' if detected else 'bad','detail':'Verification refuses this controlled manipulation. Truncation detection depends on an independently retained checkpoint; an unanchored valid prefix remains a different claim.'} for key,detected in report['detected'].items()]
        return {'label':label,'title':title,'description':description,'visual':['A TLS observation','A signed history','Independent inspection'],'metrics':[{'value':report['observations'],'label':'Signed observations'},{'value':sum(report['detected'].values()),'label':'Manipulations detected'},{'value':'0','label':'External endpoints'}],'rows':rows,'output':report}
    return {'name':'Wireledger','slug':'wireledger','icon':'shield','color':'#476da4','description':'Keep portable, signed TLS observation histories. Compare certificate changes and inspect the evidence offline.','sample_title':'A small history you can verify','insight':'A certificate renewal and a public-key change are different events. A signed history preserves what the witness observed without claiming the observer is always right.','steps':[{'title':'Observe an endpoint','description':'Verify a TLS handshake and record its public certificate evidence.'},{'title':'Sign and retain a checkpoint','description':'Chain the observations and keep trusted anchors independently.'},{'title':'Compare offline','description':'Verify signatures, inspect changes, and audit captured evidence with your own trust.'}],'features':[{'icon':'shield','title':'Portable signed observations','description':'Verify history authenticity and chain consistency under an independently trusted public key.'},{'icon':'clock','title':'Change with context','description':'Separate renewals, key changes, failed samples, and observer-clock limits.'},{'icon':'file','title':'Public evidence, inspectable','description':'Export captured certificates and metadata without revealing witness private keys.'}],'command':'python3 -m wireledger showcase -o wireledger.html','scope':'Generating this sample runs a disposable loopback-only TLS lab. Temporary keys are removed; no existing witness, personal key, or external endpoint is read. Switching states performs no network work.','footer':'A valid signature is not observer truth. Certificate changes alone are not an attack verdict; independent trust and retained checkpoints matter.','states':[state('The observations','Three observations. Renewal, then key rotation.','The actual lab verifies three loopback handshakes and signs them into a portable history.','observations'),state('Integrity checks','Controlled tampering is detected.','Modified bytes are rejected. A retained checkpoint exposes a deliberately truncated history.','integrity')]}
