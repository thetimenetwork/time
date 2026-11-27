// Build the testnet vault as a closed set of static files. This command makes no network calls.
import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { VAULT_FILES, VAULT_HEADERS, VAULT_HOST } from '../../client-v4/vault-host.mjs';

const ref = name => ({ Ref: name });
const attr = (name, field) => ({ 'Fn::GetAtt': [name, field] });
const sub = value => ({ 'Fn::Sub': value });

export function vaultStack() {
  const objectNames = [...VAULT_FILES.keys()].filter(name => name !== '/');
  // A browser visiting the AWS-issued hostname cannot start a second vault. Only published assets pass.
  const functionCode = `function handler(event) {
  var r = event.request;
  if (!r.headers.host || r.headers.host.value !== ${JSON.stringify(VAULT_HOST)}
      || Object.keys(r.querystring).length || ${JSON.stringify(['/', ...objectNames])}.indexOf(r.uri) < 0)
    return { statusCode: 404, headers: { 'cache-control': { value: 'no-store' } } };
  return r;
}`;
  return {
    AWSTemplateFormatVersion: '2010-09-09',
    Description: 'Time testnet vault. Only static application code is stored on the origin.',
    Parameters: {
      CertificateArn: { Type: 'String', AllowedPattern: 'arn:aws:acm:us-east-1:[0-9]{12}:certificate/[a-f0-9-]+', Description: 'Issued us-east-1 ACM certificate covering ' + VAULT_HOST },
      HostedZoneId: { Type: 'AWS::Route53::HostedZone::Id', Description: 'Public DNS zone containing ' + VAULT_HOST },
    },
    Resources: {
      Assets: {
        Type: 'AWS::S3::Bucket',
        Properties: {
          PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true },
          OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] },
          BucketEncryption: { ServerSideEncryptionConfiguration: [{ ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] },
        },
      },
      ReadAccess: { Type: 'AWS::CloudFront::OriginAccessControl', Properties: { OriginAccessControlConfig: {
        Name: sub('${AWS::StackName}-read'), OriginAccessControlOriginType: 's3', SigningBehavior: 'always', SigningProtocol: 'sigv4',
      } } },
      HostCheck: { Type: 'AWS::CloudFront::Function', Properties: {
        Name: sub('${AWS::StackName}-host'), AutoPublish: true,
        FunctionConfig: { Runtime: 'cloudfront-js-2.0', Comment: 'Accept only the canonical vault URL and public assets' },
        FunctionCode: functionCode,
      } },
      Headers: { Type: 'AWS::CloudFront::ResponseHeadersPolicy', Properties: { ResponseHeadersPolicyConfig: {
        Name: sub('${AWS::StackName}-headers'),
        SecurityHeadersConfig: {
          ContentSecurityPolicy: { Override: true, ContentSecurityPolicy: VAULT_HEADERS['Content-Security-Policy'] },
          ContentTypeOptions: { Override: true },
          FrameOptions: { Override: true, FrameOption: 'DENY' },
          ReferrerPolicy: { Override: true, ReferrerPolicy: 'no-referrer' },
          StrictTransportSecurity: { Override: true, AccessControlMaxAgeSec: 31536000 },
        },
        CustomHeadersConfig: { Items: ['Cache-Control', 'Permissions-Policy', 'Cross-Origin-Resource-Policy'].map(Header => ({
          Header, Value: VAULT_HEADERS[Header], Override: true,
        })) },
      } } },
      Site: { Type: 'AWS::CloudFront::Distribution', Properties: { DistributionConfig: {
        Enabled: true, Aliases: [VAULT_HOST], DefaultRootObject: 'index.html', IPV6Enabled: true,
        PriceClass: 'PriceClass_100', HttpVersion: 'http2and3',
        ViewerCertificate: { AcmCertificateArn: ref('CertificateArn'), MinimumProtocolVersion: 'TLSv1.2_2021', SslSupportMethod: 'sni-only' },
        Origins: [{ Id: 'assets', DomainName: attr('Assets', 'RegionalDomainName'),
          OriginAccessControlId: attr('ReadAccess', 'Id'), S3OriginConfig: { OriginAccessIdentity: '' } }],
        DefaultCacheBehavior: {
          TargetOriginId: 'assets', ViewerProtocolPolicy: 'https-only', AllowedMethods: ['GET', 'HEAD'],
          CachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad', ResponseHeadersPolicyId: ref('Headers'),
          FunctionAssociations: [{ EventType: 'viewer-request', FunctionARN: attr('HostCheck', 'FunctionARN') }],
        },
      } } },
      ReadPolicy: { Type: 'AWS::S3::BucketPolicy', Properties: { Bucket: ref('Assets'), PolicyDocument: {
        Version: '2012-10-17', Statement: [{ Sid: 'ReadOnlyThroughThisDistribution', Effect: 'Allow',
          Principal: { Service: 'cloudfront.amazonaws.com' }, Action: 's3:GetObject', Resource: sub('${Assets.Arn}/*'),
          Condition: { StringEquals: { 'AWS:SourceArn': sub('arn:${AWS::Partition}:cloudfront::${AWS::AccountId}:distribution/${Site}') } },
        }],
      } } },
      DNS: { Type: 'AWS::Route53::RecordSetGroup', Properties: {
        HostedZoneId: ref('HostedZoneId'), RecordSets: ['A', 'AAAA'].map(Type => ({
          Name: VAULT_HOST, Type, AliasTarget: { DNSName: attr('Site', 'DomainName'), HostedZoneId: 'Z2FDTNDATAQYW2' },
        })),
      } },
    },
    Outputs: { AssetBucket: { Value: ref('Assets') }, VaultOrigin: { Value: 'https://' + VAULT_HOST } },
  };
}

export async function buildVault(root, output) {
  // Require a fresh directory so a new bundle cannot accidentally publish files left by an older build.
  await mkdir(output);
  for (const [route, source] of VAULT_FILES) {
    const dest = path.join(output, 'assets', route === '/' ? 'index.html' : route.slice(1));
    await mkdir(path.dirname(dest), { recursive: true });
    await copyFile(path.join(root, source), dest);
  }
  await writeFile(path.join(output, 'testnet-stack.json'), JSON.stringify(vaultStack(), null, 2) + '\n');
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  if (!process.argv[2] || process.argv.length !== 3) throw new Error('Usage: node deploy/vault/build.mjs NEW_OUTPUT_DIRECTORY');
  await buildVault(fileURLToPath(new URL('../../', import.meta.url)), path.resolve(process.argv[2]));
}
