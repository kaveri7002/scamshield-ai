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
