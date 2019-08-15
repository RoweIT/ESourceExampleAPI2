/**
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
exports.handler = async (event, context) => {
  try {
    let token = event.authorizationToken;
    console.log(`Token: ${token}`);
    console.log(`Event: ${event}`);

    if (token) return generatePolicy(1, 'Allow', event.methodArn);
    else return generatePolicy(1, 'Deny', event.methodArn);
  } catch (err) {
    const response = {
      statusCode: 401,
      headers: {
        'Access-Control-Allow-Origin': '*'
      },
      body: JSON.stringify({
        error: e.message
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
