fetch('/lastfm-proxy')
  .then(response => {
    if (!response.ok) {
      throw new Error(`Network response was not ok (status: ${response.status})`);
    }
    return response.json();
  })
  .then(data => {
    console.log("Data received:", data); // Log the received data to the console

    // Check if the necessary properties exist AND are not null or empty
    if (data && data.recenttracks && data.recenttracks.track && 
        data.recenttracks.track.length > 0 && data.recenttracks.track[0] &&
        data.recenttracks.track[0].artist && data.recenttracks.track[0].name && 
        data.recenttracks.track[0].album && data.recenttracks.track[0].image && 
        data.recenttracks.track[0].url) {

      const track = data.recenttracks.track[0];
      const artist = track.artist['#text'];
      const songName = track.name;
      const albumName = track.album['#text'];
      const artworkUrl = track.image[3]['#text'];
      const nowPlaying = "Recently played";
      const songUrl = track.url;

      const trackContainer = document.getElementById('lastfm-recent-track');
      trackContainer.innerHTML = `
        <div><h2><i class="fab fa-lastfm"></i> <span class="now-playing">${nowPlaying}</span></h2>
          <div style="display: flex; align-items: left;">
            <img src="${artworkUrl}" alt="Album artwork for ${albumName}" onerror="this.src='path/to/default-image.jpg';">
            <div class="track-info">
              <h3 class="track-title"><span><a href="${songUrl}" target="_blank">${songName}</a></span></h3>
              <p>${artist}</p>
              <p>${albumName}</p>
            </div>
          </div>
        </div>
      `;
    } else {
      // Handle the case where the expected data structure is not found
      console.error("Last.fm data is missing expected properties:", data);
      document.getElementById('lastfm-recent-track').innerHTML = '<p>Unable to load your recent track. Please try again later.</p>';
    }
  })
  .catch(err => {
    console.error("Error fetching or parsing Last.fm data:", err);
    document.getElementById('lastfm-recent-track').innerHTML = '<p>Unable to load your recent track. Please try again later.</p>';
  });