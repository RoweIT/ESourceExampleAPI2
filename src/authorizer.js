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
    console.log(`Event: ${event}`);

    const authHeader = event.headers.authorization;
    const { COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID } = process.env;

    console.log(`Authorization header: ${authHeader}`);

    if (!authHeader) return callback('Unauthorized');

    const encodedCreds = authHeader.split(' ')[1];
    const plainCreds = new Buffer(encodedCreds, 'base64').toString().split(':');

    const authData = {
      Username: plainCreds[0],
      Password: plainCreds[1]
    };

    const authDetails = new AWS.AmazonCognitoIdentity.AuthenticationDetails(
      authData
    );

    const poolData = {
      UserPoolId: COGNITO_USER_POOL_ID,
      ClientId: COGNITO_CLIENT_ID
    };

    const userPool = new AWS.AmazonCognitoIdentity.CognitoUserPool(poolData);

    const userData = {
      Username: plainCreds[0],
      Pool: userPool
    };

    const cognitoUser = new AWS.AmazonCognitoIdentity.CognitoUser(userData);

    return cognitoUser.authenticateUser(authDetails, {
      onSuccess: () => {
        return generatePolicy(1, 'Allow', event.methodArn);
      },
      onFailure: () => {
        return generatePolicy(1, 'Deny', event.methodArn);
      }
    });

    // if (verified) return generatePolicy(1, 'Allow', event.methodArn);
    // else return generatePolicy(1, 'Deny', event.methodArn);
  } catch (err) {
    const response = {
      body: JSON.stringify({
        error: err.message
      })
    };

    callback(null, response);
  }

  return response;
};

// Help function to generate an IAM policy
const generatePolicy = async (principalId, effect, methodArn) => {
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
};
