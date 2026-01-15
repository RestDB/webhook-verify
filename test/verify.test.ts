import { describe, it } from 'node:test';
import assert from 'node:assert';
import { createHmac } from 'node:crypto';
import {
  verify,
  getSupportedProviders,
  isProviderSupported,
  hmac,
  timingSafeEqual,
  validateTimestamp,
  getSignature,
  getHeaderNames,
} from '../src/index.js';

describe('webhook-verify', () => {
  describe('verify function', () => {
    it('should throw for unknown provider', () => {
      assert.throws(
        () => verify('unknown' as any, 'payload', 'sig', 'secret'),
        /Unknown webhook provider/
      );
    });
  });

  describe('getSupportedProviders', () => {
    it('should return array of providers', () => {
      const providers = getSupportedProviders();
      assert.ok(Array.isArray(providers));
      assert.ok(providers.includes('stripe'));
      assert.ok(providers.includes('github'));
      assert.ok(providers.length >= 16);
    });
  });

  describe('isProviderSupported', () => {
    it('should return true for supported providers', () => {
      assert.strictEqual(isProviderSupported('stripe'), true);
      assert.strictEqual(isProviderSupported('github'), true);
    });

    it('should return false for unsupported providers', () => {
      assert.strictEqual(isProviderSupported('unknown'), false);
    });
  });

  describe('GitHub', () => {
    const secret = 'test-secret';
    const payload = '{"action":"opened"}';

    function generateGitHubSignature(body: string, key: string): string {
      const sig = createHmac('sha256', key).update(body).digest('hex');
      return `sha256=${sig}`;
    }

    it('should verify valid signature with prefix', () => {
      const signature = generateGitHubSignature(payload, secret);
      assert.strictEqual(verify('github', payload, signature, secret), true);
    });

    it('should verify valid signature without prefix', () => {
      const sig = createHmac('sha256', secret).update(payload).digest('hex');
      assert.strictEqual(verify('github', payload, sig, secret), true);
    });

    it('should reject invalid signature', () => {
      assert.strictEqual(verify('github', payload, 'sha256=invalid', secret), false);
    });

    it('should reject with wrong secret', () => {
      const signature = generateGitHubSignature(payload, secret);
      assert.strictEqual(verify('github', payload, signature, 'wrong-secret'), false);
    });
  });

  describe('Shopify', () => {
    const secret = 'test-secret';
    const payload = '{"id":123}';

    function generateShopifySignature(body: string, key: string): string {
      return createHmac('sha256', key).update(body).digest('base64');
    }

    it('should verify valid signature', () => {
      const signature = generateShopifySignature(payload, secret);
      assert.strictEqual(verify('shopify', payload, signature, secret), true);
    });

    it('should reject invalid signature', () => {
      assert.strictEqual(verify('shopify', payload, 'invalid', secret), false);
    });
  });

  describe('Stripe', () => {
    const secret = 'whsec_test';
    const payload = '{"type":"charge.succeeded"}';

    function generateStripeSignature(body: string, key: string, timestamp?: number): string {
      const ts = timestamp ?? Math.floor(Date.now() / 1000);
      const signedPayload = `${ts}.${body}`;
      const sig = createHmac('sha256', key).update(signedPayload).digest('hex');
      return `t=${ts},v1=${sig}`;
    }

    it('should verify valid signature', () => {
      const signature = generateStripeSignature(payload, secret);
      assert.strictEqual(verify('stripe', payload, signature, secret), true);
    });

    it('should reject invalid signature', () => {
      const ts = Math.floor(Date.now() / 1000);
      assert.strictEqual(verify('stripe', payload, `t=${ts},v1=invalid`, secret), false);
    });

    it('should reject expired timestamp', () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
      const signature = generateStripeSignature(payload, secret, oldTimestamp);
      assert.strictEqual(verify('stripe', payload, signature, secret), false);
    });

    it('should accept with custom tolerance', () => {
      const oldTimestamp = Math.floor(Date.now() / 1000) - 600;
      const signature = generateStripeSignature(payload, secret, oldTimestamp);
      assert.strictEqual(
        verify('stripe', payload, signature, secret, { tolerance: 700 }),
        true
      );
    });
  });

  describe('Slack', () => {
    const secret = 'test-signing-secret';
    const payload = 'token=xxx&user_id=U123';

    function generateSlackSignature(body: string, key: string, timestamp?: number): string {
      const ts = timestamp ?? Math.floor(Date.now() / 1000);
      const baseString = `v0:${ts}:${body}`;
      const sig = createHmac('sha256', key).update(baseString).digest('hex');
      return `v0=${sig},t=${ts}`;
    }

    it('should verify valid signature', () => {
      const signature = generateSlackSignature(payload, secret);
      assert.strictEqual(verify('slack', payload, signature, secret), true);
    });

    it('should reject invalid signature', () => {
      const ts = Math.floor(Date.now() / 1000);
      assert.strictEqual(verify('slack', payload, `v0=invalid,t=${ts}`, secret), false);
    });
  });

  describe('Linear', () => {
    const secret = 'test-secret';
    const payload = '{"action":"create"}';

    function generateLinearSignature(body: string, key: string): string {
      return createHmac('sha256', key).update(body).digest('hex');
    }

    it('should verify valid signature', () => {
      const signature = generateLinearSignature(payload, secret);
      assert.strictEqual(verify('linear', payload, signature, secret), true);
    });

    it('should reject invalid signature', () => {
      assert.strictEqual(verify('linear', payload, 'invalid', secret), false);
    });
  });

  describe('Vercel', () => {
    const secret = 'test-secret';
    const payload = '{"type":"deployment"}';

    function generateVercelSignature(body: string, key: string): string {
      return createHmac('sha1', key).update(body).digest('hex');
    }

    it('should verify valid signature', () => {
      const signature = generateVercelSignature(payload, secret);
      assert.strictEqual(verify('vercel', payload, signature, secret), true);
    });

    it('should reject invalid signature', () => {
      assert.strictEqual(verify('vercel', payload, 'invalid', secret), false);
    });
  });

  describe('GitLab', () => {
    const secret = 'my-secret-token';

    it('should verify valid token', () => {
      assert.strictEqual(verify('gitlab', '', secret, secret), true);
    });

    it('should reject invalid token', () => {
      assert.strictEqual(verify('gitlab', '', 'wrong-token', secret), false);
    });
  });

  describe('Intercom', () => {
    const secret = 'test-secret';
    const payload = '{"type":"notification"}';

    function generateIntercomSignature(body: string, key: string): string {
      const sig = createHmac('sha1', key).update(body).digest('hex');
      return `sha1=${sig}`;
    }

    it('should verify valid signature with prefix', () => {
      const signature = generateIntercomSignature(payload, secret);
      assert.strictEqual(verify('intercom', payload, signature, secret), true);
    });

    it('should verify valid signature without prefix', () => {
      const sig = createHmac('sha1', secret).update(payload).digest('hex');
      assert.strictEqual(verify('intercom', payload, sig, secret), true);
    });
  });

  describe('Mailchimp', () => {
    const secret = 'test-secret';
    const payload = '{"type":"subscribe"}';

    function generateMailchimpSignature(body: string, key: string): string {
      return createHmac('sha256', key).update(body).digest('base64');
    }

    it('should verify valid signature', () => {
      const signature = generateMailchimpSignature(payload, secret);
      assert.strictEqual(verify('mailchimp', payload, signature, secret), true);
    });
  });

  describe('Typeform', () => {
    const secret = 'test-secret';
    const payload = '{"form_response":{}}';

    function generateTypeformSignature(body: string, key: string): string {
      const sig = createHmac('sha256', key).update(body).digest('base64');
      return `sha256=${sig}`;
    }

    it('should verify valid signature with prefix', () => {
      const signature = generateTypeformSignature(payload, secret);
      assert.strictEqual(verify('typeform', payload, signature, secret), true);
    });

    it('should verify valid signature without prefix', () => {
      const sig = createHmac('sha256', secret).update(payload).digest('base64');
      assert.strictEqual(verify('typeform', payload, sig, secret), true);
    });
  });

  describe('Twilio', () => {
    const secret = 'test-auth-token';
    const url = 'https://example.com/webhook';
    const payload = 'AccountSid=AC123&Body=Hello';

    function generateTwilioSignature(reqUrl: string, body: string, key: string): string {
      const params = new URLSearchParams(body);
      const sortedParams: [string, string][] = [];
      for (const [k, v] of params) {
        sortedParams.push([k, v]);
      }
      sortedParams.sort((a, b) => a[0].localeCompare(b[0]));

      let signatureBase = reqUrl;
      for (const [k, v] of sortedParams) {
        signatureBase += k + v;
      }

      return createHmac('sha1', key).update(signatureBase).digest('base64');
    }

    it('should verify valid signature', () => {
      const signature = generateTwilioSignature(url, payload, secret);
      assert.strictEqual(verify('twilio', payload, signature, secret, { url }), true);
    });

    it('should reject without url option', () => {
      const signature = generateTwilioSignature(url, payload, secret);
      assert.strictEqual(verify('twilio', payload, signature, secret), false);
    });
  });

  describe('Svix', () => {
    const secretBase64 = Buffer.from('test-secret-key-1234').toString('base64');
    const secret = `whsec_${secretBase64}`;
    const payload = '{"type":"test"}';
    const msgId = 'msg_123';

    function generateSvixSignature(
      body: string,
      key: string,
      id: string,
      timestamp?: number
    ): string {
      const ts = timestamp ?? Math.floor(Date.now() / 1000);
      let secretKey: Buffer;
      if (key.startsWith('whsec_')) {
        secretKey = Buffer.from(key.slice(6), 'base64');
      } else {
        secretKey = Buffer.from(key, 'base64');
      }

      const signedPayload = `${id}.${ts}.${body}`;
      const sig = createHmac('sha256', secretKey).update(signedPayload).digest('base64');
      return `v1,${sig},t=${ts},id=${id}`;
    }

    it('should verify valid signature', () => {
      const signature = generateSvixSignature(payload, secret, msgId);
      assert.strictEqual(verify('svix', payload, signature, secret), true);
    });

    it('should reject invalid signature', () => {
      const ts = Math.floor(Date.now() / 1000);
      assert.strictEqual(
        verify('svix', payload, `v1,invalid,t=${ts},id=${msgId}`, secret),
        false
      );
    });
  });

  describe('Clerk', () => {
    // Clerk uses Svix, so basic test to ensure delegation works
    const secretBase64 = Buffer.from('test-secret-key-1234').toString('base64');
    const secret = `whsec_${secretBase64}`;
    const payload = '{"type":"user.created"}';
    const msgId = 'msg_456';

    function generateClerkSignature(
      body: string,
      key: string,
      id: string,
      timestamp?: number
    ): string {
      const ts = timestamp ?? Math.floor(Date.now() / 1000);
      let secretKey: Buffer;
      if (key.startsWith('whsec_')) {
        secretKey = Buffer.from(key.slice(6), 'base64');
      } else {
        secretKey = Buffer.from(key, 'base64');
      }

      const signedPayload = `${id}.${ts}.${body}`;
      const sig = createHmac('sha256', secretKey).update(signedPayload).digest('base64');
      return `v1,${sig},t=${ts},id=${id}`;
    }

    it('should verify valid signature (via Svix)', () => {
      const signature = generateClerkSignature(payload, secret, msgId);
      assert.strictEqual(verify('clerk', payload, signature, secret), true);
    });
  });

  describe('Generic Handlers', () => {
    describe('hmac.verify', () => {
      const secret = 'test-secret';
      const payload = '{"data":"test"}';

      it('should verify SHA256 hex signature (default)', () => {
        const sig = createHmac('sha256', secret).update(payload).digest('hex');
        assert.strictEqual(hmac.verify(payload, sig, secret), true);
      });

      it('should verify SHA256 base64 signature', () => {
        const sig = createHmac('sha256', secret).update(payload).digest('base64');
        assert.strictEqual(hmac.verify(payload, sig, secret, { encoding: 'base64' }), true);
      });

      it('should verify SHA1 signature', () => {
        const sig = createHmac('sha1', secret).update(payload).digest('hex');
        assert.strictEqual(hmac.verify(payload, sig, secret, { algorithm: 'sha1' }), true);
      });

      it('should verify SHA512 signature', () => {
        const sig = createHmac('sha512', secret).update(payload).digest('hex');
        assert.strictEqual(hmac.verify(payload, sig, secret, { algorithm: 'sha512' }), true);
      });

      it('should handle prefix stripping', () => {
        const sig = createHmac('sha256', secret).update(payload).digest('hex');
        assert.strictEqual(hmac.verify(payload, `sha256=${sig}`, secret, { prefix: 'sha256=' }), true);
      });

      it('should reject invalid signature', () => {
        assert.strictEqual(hmac.verify(payload, 'invalid', secret), false);
      });
    });

    describe('hmac.verifyWithTimestamp', () => {
      const secret = 'test-secret';
      const payload = '{"data":"test"}';

      it('should verify Stripe-style signature', () => {
        const ts = Math.floor(Date.now() / 1000);
        const signedPayload = `${ts}.${payload}`;
        const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');

        assert.strictEqual(
          hmac.verifyWithTimestamp(payload, sig, secret, ts, { format: '{timestamp}.{payload}' }),
          true
        );
      });

      it('should verify Slack-style signature', () => {
        const ts = Math.floor(Date.now() / 1000);
        const signedPayload = `v0:${ts}:${payload}`;
        const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');

        assert.strictEqual(
          hmac.verifyWithTimestamp(payload, sig, secret, ts, { format: 'v0:{timestamp}:{payload}' }),
          true
        );
      });

      it('should reject expired timestamp', () => {
        const ts = Math.floor(Date.now() / 1000) - 600;
        const signedPayload = `${ts}.${payload}`;
        const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');

        assert.strictEqual(
          hmac.verifyWithTimestamp(payload, sig, secret, ts, { format: '{timestamp}.{payload}' }),
          false
        );
      });

      it('should accept with custom tolerance', () => {
        const ts = Math.floor(Date.now() / 1000) - 600;
        const signedPayload = `${ts}.${payload}`;
        const sig = createHmac('sha256', secret).update(signedPayload).digest('hex');

        assert.strictEqual(
          hmac.verifyWithTimestamp(payload, sig, secret, ts, {
            format: '{timestamp}.{payload}',
            tolerance: 700,
          }),
          true
        );
      });
    });

    describe('hmac.sign', () => {
      const secret = 'test-secret';
      const payload = 'test-payload';

      it('should generate SHA256 hex signature', () => {
        const expected = createHmac('sha256', secret).update(payload).digest('hex');
        assert.strictEqual(hmac.sign(payload, secret), expected);
      });

      it('should generate base64 signature', () => {
        const expected = createHmac('sha256', secret).update(payload).digest('base64');
        assert.strictEqual(hmac.sign(payload, secret, { encoding: 'base64' }), expected);
      });

      it('should add prefix', () => {
        const sig = createHmac('sha256', secret).update(payload).digest('hex');
        assert.strictEqual(hmac.sign(payload, secret, { prefix: 'sha256=' }), `sha256=${sig}`);
      });
    });

    describe('timingSafeEqual', () => {
      it('should return true for equal strings', () => {
        assert.strictEqual(timingSafeEqual('test', 'test'), true);
      });

      it('should return false for different strings', () => {
        assert.strictEqual(timingSafeEqual('test', 'test2'), false);
      });

      it('should return false for different lengths', () => {
        assert.strictEqual(timingSafeEqual('short', 'longer-string'), false);
      });
    });

    describe('validateTimestamp', () => {
      it('should accept recent timestamp', () => {
        const ts = Math.floor(Date.now() / 1000);
        assert.strictEqual(validateTimestamp(ts), true);
      });

      it('should accept timestamp within tolerance', () => {
        const ts = Math.floor(Date.now() / 1000) - 200;
        assert.strictEqual(validateTimestamp(ts, 300), true);
      });

      it('should reject old timestamp', () => {
        const ts = Math.floor(Date.now() / 1000) - 400;
        assert.strictEqual(validateTimestamp(ts, 300), false);
      });

      it('should accept string timestamp', () => {
        const ts = String(Math.floor(Date.now() / 1000));
        assert.strictEqual(validateTimestamp(ts), true);
      });
    });
  });

  describe('Header Helpers', () => {
    describe('getSignature', () => {
      it('should extract Stripe signature', () => {
        const headers = { 'stripe-signature': 't=123,v1=abc' };
        const result = getSignature('stripe', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 't=123,v1=abc');
      });

      it('should extract GitHub signature', () => {
        const headers = {
          'x-hub-signature-256': 'sha256=abc123',
          'x-github-event': 'push',
        };
        const result = getSignature('github', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'sha256=abc123');
        assert.strictEqual(result.eventType, 'push');
      });

      it('should extract Shopify signature', () => {
        const headers = {
          'x-shopify-hmac-sha256': 'abc123',
          'x-shopify-topic': 'orders/create',
        };
        const result = getSignature('shopify', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'abc123');
        assert.strictEqual(result.eventType, 'orders/create');
      });

      it('should extract and format Slack signature with timestamp', () => {
        const headers = {
          'x-slack-signature': 'v0=abc123',
          'x-slack-request-timestamp': '1234567890',
        };
        const result = getSignature('slack', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'v0=abc123,t=1234567890');
        assert.strictEqual(result.rawSignature, 'v0=abc123');
        assert.strictEqual(result.timestamp, '1234567890');
      });

      it('should extract and format Discord signature with timestamp', () => {
        const headers = {
          'x-signature-ed25519': 'abc123',
          'x-signature-timestamp': '1234567890',
        };
        const result = getSignature('discord', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'abc123,t=1234567890');
        assert.strictEqual(result.timestamp, '1234567890');
      });

      it('should extract and format Svix signature with all parts', () => {
        const headers = {
          'svix-signature': 'v1,abc123',
          'svix-timestamp': '1234567890',
          'svix-id': 'msg_123',
        };
        const result = getSignature('svix', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'v1,abc123,t=1234567890,id=msg_123');
        assert.strictEqual(result.messageId, 'msg_123');
      });

      it('should extract Clerk signature (via Svix)', () => {
        const headers = {
          'svix-signature': 'v1,abc123',
          'svix-timestamp': '1234567890',
          'svix-id': 'msg_456',
        };
        const result = getSignature('clerk', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'v1,abc123,t=1234567890,id=msg_456');
      });

      it('should extract GitLab token', () => {
        const headers = {
          'x-gitlab-token': 'secret-token',
          'x-gitlab-event': 'Push Hook',
        };
        const result = getSignature('gitlab', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 'secret-token');
        assert.strictEqual(result.eventType, 'Push Hook');
      });

      it('should return null for missing headers', () => {
        assert.strictEqual(getSignature('stripe', {}), null);
        assert.strictEqual(getSignature('slack', { 'x-slack-signature': 'abc' }), null);
        assert.strictEqual(getSignature('svix', { 'svix-signature': 'abc' }), null);
      });

      it('should handle case-insensitive headers', () => {
        const headers = { 'Stripe-Signature': 't=123,v1=abc' };
        const result = getSignature('stripe', headers);
        assert.ok(result);
        assert.strictEqual(result.signature, 't=123,v1=abc');
      });

      it('should throw for unknown provider', () => {
        assert.throws(
          () => getSignature('unknown' as any, {}),
          /Unknown webhook provider/
        );
      });
    });

    describe('getHeaderNames', () => {
      it('should return Stripe header names', () => {
        const names = getHeaderNames('stripe');
        assert.strictEqual(names.signature, 'stripe-signature');
      });

      it('should return Slack header names', () => {
        const names = getHeaderNames('slack');
        assert.strictEqual(names.signature, 'x-slack-signature');
        assert.strictEqual(names.timestamp, 'x-slack-request-timestamp');
      });

      it('should return Svix header names', () => {
        const names = getHeaderNames('svix');
        assert.strictEqual(names.signature, 'svix-signature');
        assert.strictEqual(names.timestamp, 'svix-timestamp');
        assert.strictEqual(names.id, 'svix-id');
      });
    });
  });
});
