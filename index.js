#!/usr/bin/env node
const { spawn } = require('child_process')
const path = require('path')
const fs = require('fs')
const os = require('os')
const https = require('https')

const VERSION = '0.2.0'
const REPO = 'zent7x/mcp-guard'

function platformTarget() {
  const plat = os.platform()
  const arch = os.arch()
  if (plat === 'darwin' && arch === 'arm64') return 'darwin-arm64'
  if (plat === 'darwin' && arch === 'x64') return 'darwin-amd64'
  if (plat === 'linux' && arch === 'x64') return 'linux-amd64'
  if (plat === 'linux' && arch === 'arm64') return 'linux-arm64'
  if (plat === 'win32') return 'windows-amd64'
  return null
}

function binPath() {
  const target = platformTarget()
  if (!target) throw new Error('Unsupported platform: ' + os.platform() + '/' + os.arch())
  const ext = os.platform() === 'win32' ? '.exe' : ''
  return path.join(__dirname, 'bin', `mcp-guard-${target}${ext}`)
}

function download(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) return reject(new Error('Too many redirects'))
    https.get(url, res => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return resolve(download(res.headers.location, dest, redirects + 1))
      }
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode} for ${url}`))
      const tmp = dest + '.tmp'
      const file = fs.createWriteStream(tmp)
      res.pipe(file)
      file.on('finish', () => {
        file.close()
        fs.renameSync(tmp, dest)
        resolve()
      })
      file.on('error', reject)
    }).on('error', reject)
  })
}

async function install() {
  const target = platformTarget()
  if (!target) {
    console.error('mcp-guard: unsupported platform', os.platform(), os.arch())
    process.exit(1)
  }

  const ext = os.platform() === 'win32' ? '.exe' : ''
  const binDir = path.join(__dirname, 'bin')
  const dest = path.join(binDir, `mcp-guard-${target}${ext}`)

  if (fs.existsSync(dest)) return

  fs.mkdirSync(binDir, { recursive: true })

  const url = `https://github.com/${REPO}/releases/download/v${VERSION}/mcp-guard-${target}${ext}`
  process.stdout.write(`mcp-guard: downloading binary for ${target}...\n`)

  try {
    await download(url, dest)
    fs.chmodSync(dest, 0o755)
    process.stdout.write('mcp-guard: ready\n')
  } catch (err) {
    console.error('mcp-guard: download failed:', err.message)
    console.error(`  Try manually: ${url}`)
    process.exit(1)
  }
}

async function run() {
  const bin = binPath()

  if (!fs.existsSync(bin)) {
    await install()
  }

  const child = spawn(bin, process.argv.slice(2), {
    stdio: 'inherit',
    env: process.env,
  })

  child.on('error', err => {
    console.error('mcp-guard: failed to start binary:', err.message)
    process.exit(1)
  })

  child.on('exit', code => {
    process.exit(code ?? 0)
  })
}

if (require.main === module) {
  const arg = process.argv[2]
  if (arg === '__install__') {
    install().catch(err => { console.error(err.message); process.exit(1) })
  } else {
    run().catch(err => { console.error(err.message); process.exit(1) })
  }
}
