
const { expect, sinon } = require('../../../support/TestUtilities');
const Route53ARecord = require('../../../../build/impl/route53ARecord').Route53ARecord;
const route53 = require('../../../support/stubs/aws-sdk/stubRoute53');
const userPool = require('../../../support/stubs/aws-sdk/stubCognitoIdentityServiceProvider');

describe('route53ARecord', () => {

  const sandbox = sinon.createSandbox();

  afterEach(() => {
    sandbox.restore();
  });

  it('getHostedZoneId - unknown error', async () => {
    const command = new Route53ARecord({ route53 });
    sandbox.stub(route53, 'listHostedZonesByName').returns({ promise: () => Promise.reject(new Error('oops')) });
    await expect(command.getHostedZoneId()).to.eventually.be.rejectedWith('oops');
  });

  it('getHostedZoneId - no hosted zone matching domain name', async () => {
    const command = new Route53ARecord({ route53 });
    const response = {
      HostedZones: [],
      DNSName: 'overattribution.com',
      IsTruncated: false,
      MaxItems: '100'
    };
    sandbox.stub(route53, 'listHostedZonesByName').returns({ promise: () => Promise.resolve(response) });
    await expect(command.getHostedZoneId()).to.eventually.be.rejectedWith('zone');
  });

  it('getHostedZondId - success', async () => {
    const command = new Route53ARecord({ route53 });
    const response = {
      "HostedZones": [
        {
          "Id": "/hostedzone/A1B2CDEFGHIJ34",
          "Name": "overattribution.com.",
          "CallerReference": "RISWorkflow-RD:a123bc45-d67e-8901-23f4-g5678hi9j0kl",
          "Config": {
            "Comment": "HostedZone created by Route53 Registrar",
            "PrivateZone": false
          },
          "ResourceRecordSetCount": 10
        }
      ],
      "DNSName": "overattribution.com",
      "IsTruncated": false,
      "MaxItems": "100"
    };
    sandbox.stub(route53, 'listHostedZonesByName').returns({ promise: () => Promise.resolve(response) });
    const hostedZoneId = await command.getHostedZoneId('overattribution.com');
    expect(hostedZoneId).to.equal('A1B2CDEFGHIJ34');
  });

  it('getHostedZoneId - no results found', async () => {
    const command = new Route53ARecord({ route53 });
    const response = {
      "HostedZones": [],
      "DNSName": "overattribution.com",
      "IsTruncated": false,
      "MaxItems": "100"
    };
    sandbox.stub(route53, 'listHostedZonesByName').returns({ promise: () => Promise.resolve(response) });
    await expect(command.getHostedZoneId()).to.eventually.be.rejectedWith('Could not find hosted zone');
  });

  it('getHostedZoneId - no exact matches found', async () => {
    const command = new Route53ARecord({ route53 });
    const response = {
      "HostedZones": [
        {
          "Id": "/hostedzone/A1B2CDEFGHIJ34",
          "Name": "anotherdomain.com.",
          "CallerReference": "RISWorkflow-RD:a123bc45-d67e-8901-23f4-g5678hi9j0kl",
          "Config": {
            "Comment": "HostedZone created by Route53 Registrar",
            "PrivateZone": false
          },
          "ResourceRecordSetCount": 10
        }
      ],
      "DNSName": "overattribution.com",
      "IsTruncated": false,
      "MaxItems": "100"
    };
    sandbox.stub(route53, 'listHostedZonesByName').returns({ promise: () => Promise.resolve(response) });
    await expect(command.getHostedZoneId()).to.eventually.be.rejectedWith('Could not find hosted zone');
  });

  it('getHostedZoneId - paginated results');

  it('isDone - no record set found', async () => {
    const command = new Route53ARecord({ route53 });
    const response = resourceRecordSetsWithoutARecord;
    sandbox.stub(command, 'getFullDomainName').returns('nothere.overattribution.com');
    sandbox.stub(command, 'getHostedZoneId').returns('/hostedzone/A1B2CDEFGHIJ34');
    sandbox.stub(route53, 'listResourceRecordSets').returns({ promise: () => Promise.resolve(response) });
    await expect(command.isDone({ config: {}, stage: 'test' })).to.eventually.be.false;
  });

  it('isDone - record set found', async () => {
    const command = new Route53ARecord({ route53 });
    const response = resourceRecordSetsWithARecord;
    sandbox.stub(command, 'getFullDomainName').returns('sub2.overattribution.com');
    sandbox.stub(command, 'getHostedZoneId').returns(Promise.resolve('/hostedzone/A1B2CDEFGHIJ34'));
    sandbox.stub(route53, 'listResourceRecordSets').returns({ promise: () => Promise.resolve(response) });
    await expect(command.isDone({ config: {}, stage: 'test' })).to.eventually.be.true;
  });

  it('getCloudFrontDns - success', async () => {
    const command = new Route53ARecord({ userPool });
    const response = {
      "DomainDescription": {
        "UserPoolId": "us-west-2_ABcDEFg1h",
        "AWSAccountId": "123456789012",
        "Domain": "auth.overattribution.com",
        "S3Bucket": "aws-cognito-prod-pdx-assets",
        "CloudFrontDistribution": "a1bcde2f3g4hi5.cloudfront.net",
        "Version": "20190830045520",
        "Status": "ACTIVE",
        "CustomDomainConfig": {
          "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/123456a7-8b90-123c-d456-efg78h90i123"
        }
      }
    };
    sandbox.stub(userPool, 'describeUserPoolDomain').returns({ promise: () => Promise.resolve(response) })
    const dns = await command.getCloudFrontDns();
    expect(dns).to.equal('a1bcde2f3g4hi5.cloudfront.net');
  });

  it('getCloudFrontDns - no record', async () => {
    const command = new Route53ARecord({ userPool });
    const response = { DomainDescription: {} };
    sandbox.stub(userPool, 'describeUserPoolDomain').returns({ promise: () => Promise.resolve(response) });
    await expect(command.getCloudFrontDns()).to.be.rejectedWith('User Pool Domain');
  });

  it('do - unknown error', async () => {
    const command = new Route53ARecord({ route53 });
    sandbox.stub(command, 'getHostedZoneId');
    sandbox.stub(command, 'getCloudFrontDns');
    sandbox.stub(route53, 'changeResourceRecordSets').returns({ promise: () => Promise.reject(new Error('oops')) });
    await expect(command.do({ config: {}, stage: 'test' })).to.eventually.be.rejectedWith('oops');
  });

  it('undo - error', async () => {
    const command = new Route53ARecord({ route53 });
    sandbox.stub(route53, 'changeResourceRecordSets').returns({ promise: () => Promise.reject(new Error('oops')) });
    sandbox.stub(command, 'getHostedZoneId');
    sandbox.stub(command, 'getCloudFrontDns');
    await expect(command.undo({ config: {}, stage: 'test' })).to.eventually.be.rejectedWith('oops');
  });

});

const resourceRecordSetsWithoutARecord = {
  "ResourceRecordSets": [
    {
      "Name": "overattribution.com.",
      "Type": "A",
      "ResourceRecords": [],
      "AliasTarget": {
        "HostedZoneId": "A1B2CDEFGHIJ34",
        "DNSName": "sub1.overattribution.com.",
        "EvaluateTargetHealth": false
      }
    },
    {
      "Name": "overattribution.com.",
      "Type": "NS",
      "TTL": 172800,
      "ResourceRecords": [
        { "Value": "ns-123.awsdns-11.com." },
        { "Value": "ns-1234.awsdns-22.co.uk." },
        { "Value": "ns-1235.awsdns-33.org." },
        { "Value": "ns-124.awsdns-44.net." }
      ]
    },
    {
      "Name": "overattribution.com.",
      "Type": "SOA",
      "TTL": 900,
      "ResourceRecords": [ { "Value": "ns-123.awsdns-11.com. awsdns-hostmaster.amazon.com. 1 1234 123 1234567 12345" } ]
    },
    {
      "Name": "_1234567abc8d90123456e789012f3g45.overattribution.com.",
      "Type": "CNAME",
      "TTL": 300,
      "ResourceRecords": [ { "Value": "_1abc234567890d123efgh45i67890123.jklmnopqrs.tuv-validations.aws." } ]
    },
    {
      "Name": "sub2.overattribution.com.",
      "Type": "A",
      "ResourceRecords": [],
      "AliasTarget": {
        "HostedZoneId": "A1BCTDEFGHIJK2",
        "DNSName": "a1bcdefghi2jkl.cloudfront.net.",
        "EvaluateTargetHealth": false
      }
    }
  ],
  "IsTruncated": false,
  "MaxItems": "100"
};

const resourceRecordSetsWithARecord = {
  ResourceRecordSets: [
    ...resourceRecordSetsWithoutARecord.ResourceRecordSets,
    {
      "Name": "auth-test.overattribution.com.",
      "Type": "A",
      "ResourceRecords": [],
      "AliasTarget": {
        "HostedZoneId": "A1BCDEFGHIJKL2",
        "DNSName": "a1bcde2f3g4hi5.cloudfront.net.",
        "EvaluateTargetHealth": false
      }
    }
  ]
}
