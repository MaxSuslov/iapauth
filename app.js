const express = require('express');
const metadata = require('gcp-metadata');
const {OAuth2Client} = require('google-auth-library');
const axios = require('axios');


const app = express();
const oAuth2Client = new OAuth2Client();


// Cache externally fetched information for future invocations
let aud;


async function audience() {
  if (!aud && (await metadata.isAvailable())) {
    let project_number = await metadata.project('numeric-project-id');
    let project_id = await metadata.project('project-id');


    aud = '/projects/' + project_number + '/apps/' + project_id;
  }


  return aud;
}


async function validateAssertion(assertion) {
  if (!assertion) {
    return {};
  }


  // Check that the assertion's audience matches ours
  const aud = await audience();


  // Fetch the current certificates and verify the signature on the assertion
  const response = await oAuth2Client.getIapPublicKeys();
  const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
    assertion,
    response.pubkeys,
    aud,
    ['https://cloud.google.com/iap']
  );
  const payload = ticket.getPayload();


  // Return the two relevant pieces of information
  return {
    email: payload.email,
    sub: payload.sub,
  };
}




async function getUserPhotoUrl(sub) {
  const response = await axios.get(
    `https://people.googleapis.com/v1/people/${sub}?resourceName=people/${sub}&personFields=photos&key=AIzaSyCzkJdn_70EBl_nkJUzXGcdmu7XvOqMGmU`
  );
 
  return response.data.photos[0].url;
}


app.get('/', async (req, res) => {
  const assertion = req.header('X-Goog-IAP-JWT-Assertion');
  let email, sub, photo;


  try {
    const info = await validateAssertion(assertion);
    email = info.email;
    sub = info.sub.split(':')[1];
    photo = await getUserPhotoUrl(sub);
  } catch (error) {
    console.log(error);
  }




  res.status(200).send(
    `<!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>IAP/Oauth2/People API Test App</title>
      <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.2.1/css/bootstrap.min.css" 
    </head>
    <body>
      <div class="container">
        <div style="position: relative; margin-top: 10px;">
          <img class="rounded-circle" id="avatar" src="${photo}" alt="ProfilePicture" />
        </div>
      
        <h1 id="heading" class="display-4 text-center py-1">IAP Oauth App</h1>
        <p>You email is ${email}</p>
        <p>Your GoogleID is ${sub}</p>
      </div>
    </body>
    </html>`).end();
});




// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});
