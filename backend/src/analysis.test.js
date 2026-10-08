import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeMessage, analyzeUrl } from './analysis.js';

test('flags a message asking for OTP, bank details, and urgent action', () => {
  const result = analyzeMessage('Congratulations! You won a prize. Click now and enter your bank details and OTP immediately.');
  assert.equal(result.riskLevel, 'HIGH RISK');
  assert.ok(result.score >= 70);
  assert.ok(result.warnings.includes('Requests OTP'));
});

test('does not mark an ordinary message as high risk', () => {
  const result = analyzeMessage('The team meeting is at 3 PM. Please bring the project notes.');
  assert.equal(result.riskLevel, 'SAFE');
  assert.equal(result.threatType, 'Safe message');
});

test('flags suspicious URL patterns without claiming certainty', () => {
  const result = analyzeUrl('http://secure-update-bank-login.example/verify');
  assert.equal(result.riskLevel, 'SUSPICIOUS');
  assert.equal(result.status, 'Potentially suspicious');
  assert.ok(result.indicators.length > 0);
});

test('explains domain reputation signals without claiming a live lookup', () => {
  const result = analyzeUrl('https://paypa1-login.xyz/account');
  assert.equal(result.domain, 'paypa1-login.xyz');
  assert.match(result.reputationSource, /no live threat-intelligence feed/i);
  assert.ok(result.reputationChecks.some((check) => check.status === 'flagged' && /impersonation/i.test(check.label)));
  assert.ok(result.reputationChecks.some((check) => check.status === 'flagged' && /TLD/i.test(check.label)));
});

test('marks a normal HTTPS domain as unverified rather than guaranteed safe', () => {
  const result = analyzeUrl('https://example.com/');
  assert.equal(result.riskLevel, 'SAFE');
  assert.ok(result.reputationChecks.some((check) => check.label === 'HTTPS connection' && check.status === 'passed'));
  assert.match(result.recommendation, /does not prove the site is safe/i);
});

test('flags embedded credentials, punycode, and unusual ports', () => {
  const result = analyzeUrl('https://user:pass@xn--bcher-kva.xyz:8443/login');
  const flaggedChecks = result.reputationChecks.filter((check) => check.status === 'flagged');
  assert.ok(flaggedChecks.some((check) => check.label === 'Credentials embedded in URL'));
  assert.ok(flaggedChecks.some((check) => check.label === 'Internationalized (punycode) domain'));
  assert.ok(flaggedChecks.some((check) => check.label === 'Unusual destination port'));
});
