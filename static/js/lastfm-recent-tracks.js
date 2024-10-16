fetch('/lastfm-proxy')
.then(response => response.json())
.then(data => {
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
})
.catch(err => {
  console.error("Error fetching Last.fm data:", err);
  document.getElementById('lastfm-recent-track').innerHTML = '<p>Unable to load your recent track. Please try again later.</p>';
});