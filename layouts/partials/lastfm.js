const response = fetch("https://ws.audioscrobbler.com/2.0/?method=user.getrecenttracks&user=" + env.LASTFM_USERNAME + "&api_key=" + env.LASTFM_API_KEY + "&limit=1&format=json");
const data = await response.json();

let output = "";
for (const track of data.recenttracks.track.0) {
  output += `<li>${track.0.name} by ${track.0.artist['#text']}</li>`;
}

return output;