#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///
"""Build a separate, reapplicable pool-compatible Codex desktop bundle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone

SOURCE = Path('/Applications/ChatGPT.app')
TARGET = Path.home() / 'Applications/Codex Pool.app'
POOL = 'https://codex.ppflix.net/backend-api'
CHATGPT = 'https://codex.ppflix.net/pool/chatgpt/backend-api'
CHATGPT_HOME = Path.home() / '.codex-pool-chatgpt'
REVISION = 4
MARKER = 'codex-pool-patch.json'

# Capability rollouts only: do not flip migrations, kill switches, or access policies.
FLAGS = {
    '1506311413': 'Computer use',
    '410262010': 'In-app browser control',
    '410065390': 'External browser control',
    '2982604767': 'Browser extensions',
    '4131705479': 'Browser control history',
    '1146407612': 'Browser MCP apps',
    '419294242': 'Messages integration',
    '2791276931': 'Computer-use recording and replay',
    '3488289778': 'Computer history settings',
    '4100906017': 'Dictation',
    '1244621283': 'Global dictation',
    '459748632': 'Multiple windows',
    '474909459': 'Pinned conversation turns',
    '1372061905': 'Quick-window shortcuts',
    '1848317837': 'Custom pet installation',
    '2635985366': 'On-demand Mini',
    '1485025891': 'Audio visualizer and confetti settings',
    '4114442250': 'SSH remote connections',
    '2153867414': 'Remote Codex installation',
    '1315865107': 'Local executor',
}

FLAG_PATCH = (
    'function Dfn(e,t){let n=()=>',
    'function Dfn(e,t){if(!t.__codexPoolFlags){'
    'let n=t.getFeatureGate.bind(t),r=t.checkGate.bind(t),'
    'i=new Set(' + json.dumps(list(FLAGS), separators=(',', ':')) + '),'
    'a=()=>t.getContext().user.custom?.auth_method===`apikey`;'
    't.getFeatureGate=(e,t)=>{let r=a()&&i.has(e),'
    'o=n(e,r?{...t,disableExposureLog:!0}:t);'
    'return r?{...o,value:!0,details:{...o.details,reason:`LocalOverride`}}:o};'
    't.checkGate=(e,t)=>a()&&i.has(e)?!0:r(e,t);'
    't.__codexPoolFlags=!0}let n=()=>',
)

# Match complete owning expressions, not all authentication checks in the app.
PATCHES = {
    'webview/assets/app-initial-': [
        ('speed controls', 'a=i?.authMethod===`chatgpt`||i?.authMethod===`personalAccessToken`,o=i?.authMethod??null',
         'a=i?.authMethod===`chatgpt`||i?.authMethod===`personalAccessToken`||i?.authMethod===`apikey`,o=i?.authMethod??null'),
        ('voice availability', 'return t&&n&&r&&!i})})))()}function Jci(',
         'return (t||e(Sa).authMethod===`apikey`)&&n&&r&&!i})})))()}function Jci('),
        ('existing-thread voice config', 'a=rsi(t,{canUseLocalOverride:!1,override:i})',
         'a=rsi(Nke(W(oi))?.authMethod===`apikey`?{...t,existing_thread_voice_enabled:!0}:t,{canUseLocalOverride:!1,override:i})'),
    ],
    'webview/assets/app-shared-': [
        ('local capability rollouts', *FLAG_PATCH),
        ('voice auth policy', 'return e.authMethod!==`chatgpt`&&r.status===`allowed`?{status:`denied`,reason:`unsupported-auth`}:r}function pxn(',
         'return e.authMethod!==`chatgpt`&&e.authMethod!==`apikey`&&r.status===`allowed`?{status:`denied`,reason:`unsupported-auth`}:r}function pxn('),
        ('composer dictation', 'a=r||t;return{isLoading:a,isError:!1,isCapable:!a&&n&&i===`chatgpt`}}),Usi=',
         'a=r||(i!==`apikey`&&t);return{isLoading:a,isError:!1,isCapable:!a&&(i===`apikey`||n&&i===`chatgpt`)}}),Usi='),
    ],
    'webview/assets/experimental-feature-visibility-': [
        ('all supported experimental toggles',
         'return e.stage===`beta`&&e.name!==`memories`&&e.name!==`multi_agent`&&e.name!==`plugins`&&e.name!==`plugin`&&e.name!==`remote_control`&&!e.name.startsWith(`realtime_`)&&e.name!==`chronicle`&&e.name!==`workspace_dependencies`',
         'return e.stage===`beta`||e.stage===`underDevelopment`||e.stage===`stable`'),
    ],
    'webview/assets/configuration-panel-': [
        ('experimental settings heading', 'defaultMessage:`Experimental features (Beta)`',
         'defaultMessage:`Experimental features`'),
        ('experimental settings empty state', 'defaultMessage:`No beta experimental features available`',
         'defaultMessage:`No experimental features available`'),
    ],
    '.vite/build/bootstrap-': [
        ('reserved session renewal', 'async requestAuthStatus(e,t=!0){let n=await',
         'async requestAuthStatus(e,t=!0){if(e&&process.env.CODEX_API_BASE_URL===`'+CHATGPT+'`){'
         'let n=process.env.CODEX_POOL_DESKTOP_KEY;if(!n)throw Error(`Pool credential unavailable`);'
         'let r=await fetch(`https://codex.ppflix.net/pool/chatgpt/sessions`,{method:`POST`,'
         'headers:{Authorization:`Bearer ${n}`},signal:AbortSignal.timeout(30000),redirect:`error`});'
         'if(!r.ok)throw Error(`Pool session renewal failed (${r.status})`);let i=await r.json();'
         'if(i.backend_api_base!==process.env.CODEX_API_BASE_URL||i.issuer!==`https://codex.ppflix.net`)'
         'throw Error(`Pool session origin changed`);let a=Co(i.delegation_token),o=Co(this.authTokenCache?.value);'
         'if(!a||o&&(a.accountId!==o.accountId||a.userId!==o.userId))throw Error(`Pool account changed`);'
         'let s=await this.sendInternalRequest({id:`pool-session:${(0,D.randomUUID)()}`,'
         'method:`account/login/start`,params:{type:`chatgptAuthTokens`,accessToken:i.delegation_token,'
         'chatgptAccountId:a.accountId,chatgptPlanType:i.metadata.plan_type}},{timeoutMs:30000});'
         'if(s.error)throw Error(`Pool session activation failed`);e=!1}let n=await'),
        ('reserved auth normalization', 'return n.result??null}async listSkills(e)',
         'return n.result?.authMethod===`chatgptAuthTokens`&&process.env.CODEX_API_BASE_URL===`'+CHATGPT+'`?'
         '{...n.result,authMethod:`chatgpt`}:n.result??null}async listSkills(e)'),
        ('native token read', 'n?.authMethod===`chatgpt`||n?.authMethod===`chatgptAuthTokens`?n.authToken??null:null,i=wo(r)',
         'n?.authMethod===`chatgpt`||n?.authMethod===`chatgptAuthTokens`||process.env.CODEX_API_BASE_URL===`'+POOL+'`&&n?.authMethod===`apikey`?n.authToken??null:null,i=wo(r)'),
        ('native token refresh', 't?.authMethod===`chatgpt`||t?.authMethod===`chatgptAuthTokens`?t.authToken??null:null;if(this.authTokenCache===e)',
         't?.authMethod===`chatgpt`||t?.authMethod===`chatgptAuthTokens`||process.env.CODEX_API_BASE_URL===`'+POOL+'`&&t?.authMethod===`apikey`?t.authToken??null:null;if(this.authTokenCache===e)'),
        ('pool routing', 'if(i.data.account?.type!==`chatgpt`)return null;let o=i.data.workspaceRouting;',
         'if(i.data.account?.type===`apiKey`&&process.env.CODEX_API_BASE_URL===`'+POOL+'`)return{kind:`legacy`};if(i.data.account?.type!==`chatgpt`)return null;let o=i.data.workspaceRouting;'),
    ],
}


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


def read_header(path):
    with path.open('rb') as stream:
        prefix = stream.read(16)
        header_bytes = stream.read(struct.unpack_from('<I', prefix, 12)[0])
    return json.loads(header_bytes), 8 + struct.unpack_from('<I', prefix, 4)[0], header_bytes


def entries(tree, prefix=''):
    for name, value in tree['files'].items():
        path = prefix + name
        if 'files' in value:
            yield from entries(value, path + '/')
        else:
            yield path, value


def prepare(archive):
    tree, base, header_bytes = read_header(archive)
    found = list(entries(tree))
    replacements = {}
    names = []
    with archive.open('rb') as stream:
        for prefix, patches in PATCHES.items():
            matches = [(path, item) for path, item in found if path.startswith(prefix) and path.endswith('.js')]
            if len(matches) != 1:
                raise RuntimeError(f'Update not supported: expected one {prefix} file')
            path, item = matches[0]
            stream.seek(base + int(item['offset']))
            text = stream.read(item['size']).decode()
            for name, old, new in patches:
                count = text.count(old)
                if count != 1:
                    raise RuntimeError(f'Update not supported: {name} anchor matched {count} times; original app unchanged')
                text = text.replace(old, new, 1)
                names.append(name)
            replacements[path] = text.encode()
    return tree, base, replacements, names, hashlib.sha256(header_bytes).hexdigest()


def integrity(data, block_size):
    return {'algorithm': 'SHA256', 'hash': hashlib.sha256(data).hexdigest(),
            'blockSize': block_size,
            'blocks': [hashlib.sha256(data[i:i + block_size]).hexdigest() for i in range(0, len(data), block_size)]}


def rebuild(path, tree, old_base, replacements):
    packed = [(name, item) for name, item in entries(tree) if 'offset' in item and not item.get('unpacked')]
    packed.sort(key=lambda pair: int(pair[1]['offset']))
    old_offsets = {name: int(item['offset']) for name, item in packed}
    offset = 0
    for name, item in packed:
        item['offset'] = str(offset)
        if name in replacements:
            data = replacements[name]
            item['size'] = len(data)
            item['integrity'] = integrity(data, item.get('integrity', {}).get('blockSize', 4194304))
        offset += item['size']
    encoded = json.dumps(tree, separators=(',', ':'), ensure_ascii=False).encode()
    # Chromium Pickle: size pickle, then string pickle with four-byte padding.
    payload_size = (4 + len(encoded) + 3) & ~3
    prefix = struct.pack('<IIII', 4, 4 + payload_size, payload_size, len(encoded))
    new = path.with_suffix('.asar.pool-new')
    with path.open('rb') as source, new.open('wb') as dest:
        dest.write(prefix)
        dest.write(encoded)
        dest.write(bytes(payload_size - 4 - len(encoded)))
        for name, item in packed:
            if name in replacements:
                dest.write(replacements[name])
                continue
            source.seek(old_base + old_offsets[name])
            remaining = item['size']
            while remaining:
                chunk = source.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise RuntimeError('Truncated source archive')
                dest.write(chunk)
                remaining -= len(chunk)
    os.replace(new, path)
    return hashlib.sha256(encoded).hexdigest()


def update_digest(app, original, updated):
    sentinel = b'AGbevlPCksUGKNL8TSn7wGmJEuJsXb2A'

    def digest(metadata):
        value = ''.join(path + item['algorithm'] + item['hash']
                        for path, item in sorted(metadata.items()))
        return hashlib.sha256(value.encode()).digest()

    matches = 0
    for path in (app / 'Contents/Frameworks').rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open('rb') as stream:
            if stream.read(4) not in (b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe'):
                continue
        data = path.read_bytes()
        slot = data.find(sentinel)
        if slot < 0:
            continue
        if data.find(sentinel, slot + 1) >= 0 or data[slot + 32:slot + 34] != b'\x01\x01':
            raise RuntimeError('Unsupported embedded archive integrity layout')
        if data[slot + 34:slot + 66] != digest(original):
            raise RuntimeError('Original embedded archive digest mismatch')
        # Preserve validation: replace the expected digest, never disable the fuse.
        with path.open('r+b') as stream:
            stream.seek(slot + 34)
            stream.write(digest(updated))
        matches += 1
    if matches != 1:
        raise RuntimeError(f'Expected one embedded archive digest, found {matches}')


def source_version():
    return plistlib.loads((SOURCE / 'Contents/Info.plist').read_bytes())['CFBundleShortVersionString']


def current(digest):
    marker = TARGET / 'Contents/Resources' / MARKER
    if not marker.exists():
        return False
    state = json.loads(marker.read_text())
    return state.get('sourceHeader') == digest and state.get('revision') == REVISION


def install(prepared):
    tree, base, replacements, names, digest = prepared
    if current(digest):
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', str(TARGET))
        print(f'Current: {TARGET}')
        return
    if TARGET.exists() and not (TARGET / 'Contents/Resources' / MARKER).exists():
        raise RuntimeError(f'Refusing to replace an unrecognized app: {TARGET}')
    processes = run('/bin/ps', '-axo', 'command=').decode()
    if str(TARGET / 'Contents/MacOS/ChatGPT') in processes:
        raise RuntimeError('Quit Codex Pool before reapplying; the original ChatGPT app can stay open')
    build = Path(tempfile.mkdtemp(prefix='codex-pool-build-', dir=TARGET.parent))
    candidate = build / TARGET.name
    try:
        run('/usr/bin/ditto', str(SOURCE), str(candidate))
        archive = candidate / 'Contents/Resources/app.asar'
        header_hash = rebuild(archive, tree, base, replacements)
        plist_path = candidate / 'Contents/Info.plist'
        info = plistlib.loads(plist_path.read_bytes())
        info['CFBundleDisplayName'] = 'Codex Pool'
        info['CFBundleName'] = 'Codex Pool'
        info.setdefault('LSEnvironment', {})['CODEX_API_BASE_URL'] = POOL
        original_integrity = json.loads(json.dumps(info['ElectronAsarIntegrity']))
        info['ElectronAsarIntegrity']['Resources/app.asar']['hash'] = header_hash
        update_digest(candidate, original_integrity, info['ElectronAsarIntegrity'])
        plist_path.write_bytes(plistlib.dumps(info))
        state = {'revision': REVISION, 'sourceVersion': source_version(), 'sourceHeader': digest,
                 'pool': POOL, 'patches': names, 'flags': FLAGS}
        (candidate / 'Contents/Resources' / MARKER).write_text(json.dumps(state, indent=2) + '\n')
        # Ad-hoc builds cannot claim OpenAI's team, keychain, or notification groups.
        raw = run('/usr/bin/codesign', '-d', '--entitlements', ':-', str(SOURCE))
        entitlements = plistlib.loads(raw)
        for key in ('com.apple.application-identifier', 'com.apple.developer.team-identifier',
                    'com.apple.developer.aps-environment', 'com.apple.security.application-groups',
                    'keychain-access-groups'):
            entitlements.pop(key, None)
        entitlements_path = build / 'entitlements.plist'
        entitlements_path.write_bytes(plistlib.dumps(entitlements))
        run('/usr/bin/codesign', '--force', '--deep', '--sign', '-', '--options', 'runtime',
            '--entitlements', str(entitlements_path), str(candidate))
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', str(candidate))
        previous = TARGET.with_name('Codex Pool.previous.app')
        if previous.exists():
            if not (previous / 'Contents/Resources' / MARKER).exists():
                raise RuntimeError('Unrecognized previous app; refusing to replace it')
            shutil.rmtree(previous)
        if TARGET.exists():
            os.rename(TARGET, previous)
        try:
            os.rename(candidate, TARGET)
        except BaseException:
            if previous.exists() and not TARGET.exists():
                os.rename(previous, TARGET)
            raise
        print(f'Installed: {TARGET} (source {state["sourceVersion"]}, {len(names)} patches)')
    finally:
        shutil.rmtree(build)


def private_write(path, text):
    descriptor, temporary = tempfile.mkstemp(prefix='.pool-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w') as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def chatgpt_config(text):
    config = tomllib.loads(text)
    provider = config.get('model_provider')
    if provider != 'codex-pool':
        raise RuntimeError('Select the codex-pool provider before launching ChatGPT')
    if config.get('service_tier') != 'default':
        raise RuntimeError('The desktop pool profile must use the default service tier')
    text, count = re.subn(r'^chatgpt_base_url\s*=.*$', 'chatgpt_base_url = ' + json.dumps(CHATGPT), text, flags=re.M)
    if count != 1:
        raise RuntimeError('Expected one ChatGPT backend setting')
    pattern = r'(\[model_providers\.codex-pool\]\n)([^\[]*)'
    def update(match):
        body = match[2]
        body = re.sub(r'^env_key\s*=.*\n?', '', body, flags=re.M)
        body = re.sub(r'^requires_openai_auth\s*=.*$', 'requires_openai_auth = true', body, flags=re.M)
        return match[1] + 'env_key = "CODEX_POOL_DESKTOP_KEY"\n' + body
    text, count = re.subn(pattern, update, text, flags=re.M)
    if count != 1:
        raise RuntimeError('Expected one codex-pool provider section')
    parsed = tomllib.loads(text)
    if parsed['model_providers']['codex-pool'].get('requires_openai_auth') is not True:
        raise RuntimeError('ChatGPT authentication must stay enabled')
    return text


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, url):
        raise RuntimeError('Pool session redirect refused')


def launch_chatgpt():
    original = Path.home() / '.codex'
    key = json.loads((original / 'auth.json').read_text()).get('OPENAI_API_KEY')
    if not isinstance(key, str) or not key:
        raise RuntimeError('A pool API key is required')
    config = chatgpt_config((original / 'config.toml').read_text())
    request = urllib.request.Request('https://codex.ppflix.net/pool/chatgpt/sessions',
                                     data=b'{}', headers={'Authorization': 'Bearer ' + key,
                                     'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            session = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'Pool ChatGPT session failed (HTTP {error.code}); check the reserved account') from None
    metadata = session.get('metadata', {})
    token = session.get('delegation_token')
    if session.get('issuer') != 'https://codex.ppflix.net' or session.get('backend_api_base') != CHATGPT:
        raise RuntimeError('Pool session origin does not match')
    if not token or not metadata.get('account_id') or not metadata.get('user_id') or metadata.get('plan_type') not in ('pro', 'promax'):
        raise RuntimeError('Pool Pro membership is unavailable')
    marker = CHATGPT_HOME / '.pool-desktop-profile'
    if CHATGPT_HOME.exists() and not marker.exists():
        raise RuntimeError('Refusing to overwrite an unrecognized ChatGPT profile')
    CHATGPT_HOME.mkdir(mode=0o700, exist_ok=True)
    os.chmod(CHATGPT_HOME, 0o700)
    profile = CHATGPT_HOME / 'desktop'
    profile.mkdir(mode=0o700, exist_ok=True)
    auth = {'auth_mode': 'chatgpt', 'OPENAI_API_KEY': None,
            'tokens': {'id_token': token, 'access_token': token, 'refresh_token': '',
                       'account_id': metadata['account_id']},
            'last_refresh': datetime.now(timezone.utc).isoformat()}
    private_write(marker, 'reserved-chatgpt\n')
    private_write(CHATGPT_HOME / 'config.toml', config)
    private_write(CHATGPT_HOME / 'auth.json', json.dumps(auth))
    environment = os.environ.copy()
    environment.update(CODEX_HOME=str(CHATGPT_HOME), CODEX_API_BASE_URL=CHATGPT,
                       CODEX_ELECTRON_USER_DATA_PATH=str(profile), CODEX_POOL_DESKTOP_KEY=key)
    subprocess.Popen([str(TARGET / 'Contents/MacOS/ChatGPT'), '--user-data-dir=' + str(profile)],
                     env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    print('Launched reserved ChatGPT profile')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['check', 'install', 'launch', 'chatgpt'], nargs='?', default='check')
    args = parser.parse_args()
    prepared = prepare(SOURCE / 'Contents/Resources/app.asar')
    if args.action == 'check':
        print(json.dumps({'sourceVersion': source_version(), 'patches': prepared[3],
                          'installedCurrent': current(prepared[4]), 'target': str(TARGET),
                          'flags': FLAGS}, indent=2))
        return
    install(prepared)
    if args.action == 'chatgpt':
        launch_chatgpt()
    if args.action == 'launch':
        run('/usr/bin/open', '--env', 'CODEX_API_BASE_URL=' + POOL, str(TARGET))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(str(error))
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr.decode(errors='replace'))
        raise SystemExit(1)
