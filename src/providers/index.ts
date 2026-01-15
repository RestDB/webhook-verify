import { clerk } from './clerk.js';
import { crystallize } from './crystallize.js';
import { discord } from './discord.js';
import { github } from './github.js';
import { gitlab } from './gitlab.js';
import { hubspot } from './hubspot.js';
import { intercom } from './intercom.js';
import { linear } from './linear.js';
import { mailchimp } from './mailchimp.js';
import { paddle } from './paddle.js';
import { segment } from './segment.js';
import { sendgrid } from './sendgrid.js';
import { shopify } from './shopify.js';
import { slack } from './slack.js';
import { square } from './square.js';
import { stripe } from './stripe.js';
import { svix } from './svix.js';
import { twilio } from './twilio.js';
import { typeform } from './typeform.js';
import { vercel } from './vercel.js';
import { zendesk } from './zendesk.js';

import type { Provider, ProviderVerifier } from '../types.js';

/**
 * Registry of all supported webhook providers
 */
export const providers: Record<Provider, ProviderVerifier> = {
  clerk,
  crystallize,
  discord,
  github,
  gitlab,
  hubspot,
  intercom,
  linear,
  mailchimp,
  paddle,
  segment,
  sendgrid,
  shopify,
  slack,
  square,
  stripe,
  svix,
  twilio,
  typeform,
  vercel,
  zendesk,
};

export {
  clerk,
  crystallize,
  discord,
  github,
  gitlab,
  hubspot,
  intercom,
  linear,
  mailchimp,
  paddle,
  segment,
  sendgrid,
  shopify,
  slack,
  square,
  stripe,
  svix,
  twilio,
  typeform,
  vercel,
  zendesk,
};
