async function fetchLastFmTracks(user, apikey) {
  const apiKey = 'YOUR_LAST_FM_API_KEY'; 
  const apiUrl = `https://ws.audioscrobbler.com/2.0/?method=user.getrecenttracks&user=${user}&api_key=${apiKey}&limit=1&format=json`;

  try {
    const response = await fetch(apiUrl);
    const data = await response.json();

    // Process the 'data.recenttracks.track' array and update your website content
    console.log(data.recenttracks.track); 
  } catch (error) {
    console.error('Error fetching Last.fm data:', error);
    // Handle errors gracefully (e.g., display an error message to the user)
  }
}

// Call the function
fetchLastFmTracks(${LASTFM_USERNAME}, ${LASTFM_API_KEY});