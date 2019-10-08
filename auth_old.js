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
    const identity = new AWS.CognitoIdentityServiceProvider({
      region: 'eu-west-2'
    });

    console.log(`Event: ${JSON.stringify(event)}`);
    console.log(`ENV: ${JSON.stringify(process.env)}`);

    const authHeader = event.authorizationToken;
    const { COGNITO_USER_POOL_ID, COGNITO_CLIENT_ID } = process.env;

    console.log(`Authorization header: ${authHeader}`);

    if (!authHeader) return callback('Unauthorized');

    const plainCreds = Buffer.from(
      authHeader.split(' ')[1],
      'base64'
    ).toString();

    const authData = {
      Username: plainCreds[0],
      Password: plainCreds[1]
    };

    const authDetails = identity.AuthenticationDetails(authData);

    const poolData = {
      UserPoolId: COGNITO_USER_POOL_ID,
      ClientId: COGNITO_CLIENT_ID
    };

    const userPool = identity.CognitoUserPool(poolData);

    const userData = {
      Username: plainCreds[0],
      Pool: userPool
    };

    const cognitoUser = identity.CognitoUser(userData);

    console.log(cognitoUser);
    console.log(generatePolicy(plainCreds[0], 'Allow', event.methodArn););

    return cognitoUser.authenticateUser(authDetails, {
      onSuccess: () => {
        return generatePolicy(plainCreds[0], 'Allow', event.methodArn);
      },
      onFailure: () => {
        return generatePolicy(plainCreds[0], 'Deny', event.methodArn);
      }
    });

    // if (verified) return generatePolicy(1, 'Allow', event.methodArn);
    // else return generatePolicy(1, 'Deny', event.methodArn);
  } catch (err) {
    callback(null, err);
  }
};

// Help function to generate an IAM policy
const generatePolicy = async (principalId, effect, methodArn) => {
  console.log('Generating Policy...');

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

  console.log('POLICY: ', JSON.stringify(authResponse));

  return authResponse;
};
