'use strict';

const $ = (id) => document.getElementById(id);

async function loadStatus() {
  try {
    const response = await fetch('/account/api/registration', { cache: 'no-store' });
    if (!response.ok) throw new Error('Registration status is unavailable.');
    const status = await response.json();
    $('checking').hidden = true;
    $('closed').hidden = status.enabled;
    $('signup-form').hidden = !status.enabled;
    if (status.enabled) $('name').focus();
  } catch (error) {
    $('checking').textContent = error instanceof Error
      ? error.message
      : 'Registration status is unavailable.';
  }
}

$('signup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('form-message').textContent = '';
  if ($('password').value !== $('confirm-password').value) {
    $('form-message').textContent = 'Passwords do not match.';
    $('confirm-password').focus();
    return;
  }
  $('create').disabled = true;
  $('create').textContent = 'Creating account…';
  try {
    const response = await fetch('/account/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: $('name').value,
        email: $('email').value,
        password: $('password').value,
      }),
    });
    const result = await response.json();
    if (!response.ok || !result.created) throw new Error(result.message || 'Registration failed.');
    $('signup-form').reset();
    $('signup-form').hidden = true;
    $('success').hidden = false;
  } catch (error) {
    $('form-message').textContent = error instanceof Error ? error.message : 'Registration failed.';
  } finally {
    $('create').disabled = false;
    $('create').textContent = 'Create account';
  }
});

loadStatus();
