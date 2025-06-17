fetch('https://lastfmapi.last-continue103.workers.dev')
  .then(response => {
    if (!response.ok) {
      throw new Error(`Network response was not ok (status: ${response.status})`);
    }
    return response.json();
  })
  .then(data => {
    console.log("Data received:", data);
    // Check if data and required properties exist
    if (data?.artist && data?.name && data?.album && data?.artworkUrl && data?.songUrl) { 
      const { artist, name: songName, album: albumName, artworkUrl, songUrl } = data;

      const trackContainer = document.getElementById('lastfm-recent-track');
      trackContainer.innerHTML = ` 
        <div>
          <h2><i class="fab fa-lastfm"></i> <span class="now-playing">Recently Played</span></h2> 
          <div style="display: flex; align-items: left;">
            <img src="${artworkUrl}" alt="Album artwork for ${albumName}" onerror="this.src='/images/default-album.webp';">
            <div class="track-info">
              <h3 class="track-title"><span><a href="${songUrl}" target="_blank">${songName}</a></span></h3>
              <p class="artist">${artist}</p>
              <p class="album">${albumName}</p> 
            </div>
          </div>
        </div>
      `;
    } else {
      console.error("Last.fm data is missing expected properties:", data);
      document.getElementById('lastfm-recent-track').innerHTML = '<p>Unable to load your recent track. Please try again later.</p>';
    }
  })
  .catch(err => {
    console.error("Error fetching or parsing Last.fm data:", err);
    document.getElementById('lastfm-recent-track').innerHTML = `<p>Unable to load your recent track: ${err.message}</p>`;
  });