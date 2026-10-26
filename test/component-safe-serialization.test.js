'use strict'

const test = require('tape')
const fastURI = require('..')

test('port serialization rejects non-digit values', (t) => {
  const malformedPorts = [
    '@127.0.0.1:8124',
    '8080@evil.example',
    '8080/path',
    '8080?query',
    '8080#fragment',
    '8080:9000',
    '-1',
    '1.5',
    1.5,
    NaN,
    Infinity,
    '\u0661'
  ]

  for (const port of malformedPorts) {
    t.throws(
      () => fastURI.serialize({ scheme: 'http', host: 'trusted.example', port, path: '/app' }),
      /URI port is malformed\./,
      String(port)
    )
  }

  t.throws(
    () => fastURI.normalize({ scheme: 'http', host: 'trusted.example', port: '@evil.example' }),
    /URI port is malformed\./,
    'object normalization rejects a malformed port'
  )
  t.equal(
    fastURI.equal(
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' },
      { scheme: 'http', host: 'trusted.example', port: '@evil.example' }
    ),
    false,
    'object equality fails closed for a malformed port'
  )
  t.end()
})

test('port serialization preserves RFC 3986 digit values', (t) => {
  const validPorts = [
    [8080, '8080'],
    ['8080', '8080'],
    ['00080', '00080'],
    ['', '']
  ]

  for (const [port, expected] of validPorts) {
    t.equal(
      fastURI.serialize({ scheme: 'uri', host: 'example.test', port }),
      `uri://example.test:${expected}`,
      JSON.stringify(port)
    )
  }
  t.end()
})

test('port serialization cannot move the authority to an attacker host', (t) => {
  const component = { scheme: 'http', host: 'trusted.example', port: '@127.0.0.1:8124', path: '/app' }

  t.throws(
    () => fastURI.serialize(component),
    /URI port is malformed\./,
    'serialize does not emit http://trusted.example:@127.0.0.1:8124/app'
  )
  t.equal(
    fastURI.equal(component, 'http://trusted.example:@127.0.0.1:8124/app'),
    false,
    'object equality does not match the injected authority'
  )
  t.equal(
    fastURI.equal('http://trusted.example:@127.0.0.1:8124/app', component),
    false,
    'object equality does not match the injected authority in either operand order'
  )
  t.equal(
    fastURI.serialize(fastURI.parse('http://trusted.example:8124/app')),
    'http://trusted.example:8124/app',
    'parsed digit ports still serialize unchanged'
  )
  t.end()
})

test('component resolution rejects a malformed port', (t) => {
  t.throws(
    () => fastURI.resolveComponent(
      { scheme: 'http', host: 'trusted.example', port: '@127.0.0.1:8124', path: '/app' },
      { path: 'next' }
    ),
    /URI port is malformed\./,
    'malformed base port is rejected'
  )
  t.throws(
    () => fastURI.resolveComponent(
      { scheme: 'http', host: 'trusted.example', path: '/app' },
      { host: 'trusted.example', port: '@127.0.0.1:8124', path: '/next' }
    ),
    /URI port is malformed\./,
    'malformed relative port is rejected'
  )

  const resolved = fastURI.resolveComponent(
    { scheme: 'http', host: 'trusted.example', port: 8124, path: '/app' },
    { path: 'next' }
  )
  t.equal(resolved.host, 'trusted.example', 'digit ports keep the trusted host')
  t.equal(resolved.port, 8124, 'digit ports are preserved')
  t.end()
})
