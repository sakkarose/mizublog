fetch('/lastfm-proxy')
  .then(response => {
    if (!response.ok) {
      throw new Error(`Network response was not ok (status: ${response.status})`);
    }
    return response.json();
  })
  .then(data => {
    console.log("Data received:", data); 

    // Access properties directly from the data object
    const artist = data.artist;
    const songName = data.name;
    const albumName = data.album;
    const artworkUrl = data.artworkUrl;
    const songUrl = data.songUrl;
    const nowPlaying = "Recently played";

    const trackContainer = document.getElementById('lastfm-recent-track');
    trackContainer.innerHTML = `
      <div><h2><i class="fab fa-lastfm"></i> <span class="now-playing">${nowPlaying}</span></h2>
        <div style="display: flex; align-items: left;">
          <img src="${artworkUrl}" alt="Album artwork for ${albumName}" onerror="this.src='path/to/default-image.jpg';">
          <div class="track-info">
            <h3 class="track-title"><span><a href="${songUrl}" target="_blank">${songName}</a></span></h3>
            <p class="artist">${artist}</p> <p class="album">${albumName}</p> 
          </div>
        </div>
      </div>
    `;
  })
  .catch(err => {
    console.error("Error fetching or parsing Last.fm data:", err);
    document.getElementById('lastfm-recent-track').innerHTML = '<p>Unable to load your recent track. Please try again later.</p>';
  });