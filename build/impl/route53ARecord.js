
const AWS = require('aws-sdk');
const BuildCommand = require('../BuildCommand');

const HOSTED_ZONE_FOR_CLOUD_FORMATION = 'Z2FDTNDATAQYW2'; // https://docs.aws.amazon.com/general/latest/gr/rande.html#elb_region

class Route53ARecord extends BuildCommand {

  constructor(options) {
    super(options);
    options = options || {};
    this.route53 = options.route53 || new AWS.Route53({ apiVersion: '2013-04-01', region: 'us-west-2' });
    this.userPool = options.userPool
      || new AWS.CognitoIdentityServiceProvider({ apiVersion: '2016-04-18', region: 'us-west-2' });
  }

  getName() {
    return 'route53ARecord';
  }

  async do(options) {
    options = options || {};
    const { config, stage } = options;
    const HostedZoneId = await this.getHostedZoneId(config.domain);
    const DNSName = await this.getCloudFrontDns(config.domain, config.subDomain, stage);
    await this.route53.changeResourceRecordSets({
      ChangeBatch: {
        Changes: [
          {
            Action: 'CREATE',
            ResourceRecordSet: {
              Name: this.getFullDomainName(config.domain, config.subDomain, stage),
              Type: 'A',
              AliasTarget: {
                DNSName,
                EvaluateTargetHealth: false,
                HostedZoneId: HOSTED_ZONE_FOR_CLOUD_FORMATION
              }
            }
          }
        ],
        Comment: 'Alias to CloudFront for User Pool'
      },
      HostedZoneId
    }).promise();
  }

  async undo(options) {
    options = options || {};
    const { config, stage } = options;
    const HostedZoneId = await this.getHostedZoneId(config.domain);
    const DNSName = await this.getCloudFrontDns(config.domain, config.subDomain, stage);
    const ResourceRecordSet = {
      Name: this.getFullDomainName(config.domain, config.subDomain, stage),
      Type: 'A',
      AliasTarget: {
        DNSName,
        EvaluateTargetHealth: false,
        HostedZoneId: HOSTED_ZONE_FOR_CLOUD_FORMATION
      }
    };
    await this.route53.changeResourceRecordSets({
      ChangeBatch: {
        Changes: [
          {
            Action: 'DELETE',
            ResourceRecordSet
          }
        ],
        // Comment: 'Alias to CloudFront for User Pool'
      },
      HostedZoneId
    }).promise();

  }

  async isDone(options) {
    options = options || {};
    const { config, stage } = options;
    const fullDomainName = this.getFullDomainName(config.domain, config.subDomain, stage);
    const HostedZoneId = await this.getHostedZoneId(config.domain);
    const response = await this.route53.listResourceRecordSets({ HostedZoneId }).promise();
    for (let record of response.ResourceRecordSets) {
      if (record.Name !== `${fullDomainName}.`) continue;
      if (record.Type !== 'A') continue;
      if (!record.AliasTarget) continue;
      return true;
    }
    return false;
  }

  async getHostedZoneId(domain) {
    const response = await this.route53.listHostedZonesByName({ DNSName: `${domain}.` }).promise();
    if (!response.HostedZones || response.HostedZones.length === 0)
    throw new Error(`Could not find hosted zone for domain=${domain}.`);
    for (let hostedZone of response.HostedZones) if (hostedZone.Name === `${domain}.`)
    return hostedZone.Id.replace('/hostedzone/', '');
    throw new Error(`Could not find hosted zone for domain=${domain}.`);
  }

  async getCloudFrontDns(domain, subDomain, stage) {
    let response = await this.userPool.describeUserPoolDomain({
      Domain: this.getFullDomainName(domain, subDomain, stage)
    }).promise();
    if (!response.DomainDescription || !response.DomainDescription.CloudFrontDistribution)
      throw new Error('No User Pool Domain configured.');
    return response.DomainDescription.CloudFrontDistribution;
  }

  getFullDomainName(domain, subDomain, stage) {
    return stage === 'prod'
      ? `${subDomain}.${domain}`
      : `${subDomain}-${stage}.${domain}`;
  }

}

module.exports = new Route53ARecord();
module.exports.Route53ARecord = Route53ARecord;
