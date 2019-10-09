const AWS = require('aws-sdk');

/**
 *
 *
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Context doc: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html
 * @param {Object} context
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 *
 */
exports.handler = async (event, context, callback) => {
  try {
    const cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider(
      {
        region: 'eu-west-2'
      }
    );

    console.log(`Event: ${JSON.stringify(event)}`);
    console.log(`Env: ${JSON.stringify(process.env)}`);

    const authHeader = event.authorizationToken;
    const { COGNITO_CLIENT_ID } = process.env;

    console.log(`Authorization header: ${authHeader}`);

    if (!authHeader) return callback('Unauthorized');

    const plainCreds = Buffer.from(authHeader.split(' ')[1], 'base64')
      .toString()
      .split(':');

    const params = {
      AuthFlow: 'USER_PASSWORD_AUTH',
      ClientId: COGNITO_CLIENT_ID,
      AuthParameters: {
        USERNAME: plainCreds[0],
        PASSWORD: plainCreds[1]
      }
    };

    return cognitoidentityserviceprovider
      .initiateAuth(params, () => {})
      .promise()
      .then(res => {
        console.log(JSON.stringify(res));
        return generatePolicy(plainCreds[0], 'Allow', event.methodArn);
      })
      .catch(err => {
        console.error(JSON.stringify(err));
        return generatePolicy(plainCreds[0], 'Deny', event.methodArn);
      });
  } catch (err) {
    callback(Error(err));
  }
};

// Help function to generate an IAM policy
function generatePolicy(principalId, effect, methodArn) {
  let authResponse = {};

  authResponse.principalId = principalId;
  if (effect && methodArn) {
    let policyDocument = {};
    policyDocument.Version = '2012-10-17';
    policyDocument.Statement = [
      {
        Sid: 'FirstStatement',
        Action: 'execute-api:Invoke',
        Effect: effect,
        Resource: methodArn
      }
    ];

    authResponse.policyDocument = policyDocument;
  }

  return authResponse;
}
