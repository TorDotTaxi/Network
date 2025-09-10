
document.addEventListener("DOMContentLoaded", function() {
  const lockedOverlay = document.getElementById("locked-overlay");
  const lockedContent = document.getElementById("locked-content");

  // Theo dõi phần comment iframe để phát hiện comment thành công
  const commentIframe = document.getElementById("comment-editor");

  if (commentIframe) {
    const observer = new MutationObserver(() => {
      if (commentIframe.contentWindow.document.body.innerText.includes("Your comment has been published")) {
        openSharePopup();
      }
    });
    observer.observe(commentIframe, { subtree: true, childList: true });
  }

  // Mở popup chia sẻ Facebook
  window.openSharePopup = function() {
    const postUrl = window.location.href;
    const fbShareUrl = "https://www.facebook.com/sharer/sharer.php?u=" + encodeURIComponent(postUrl);
    const popup = window.open(fbShareUrl, "_blank", "width=600,height=400");

    const pollTimer = setInterval(function() {
      if (popup.closed) {
        clearInterval(pollTimer);
        unlockContent();
      }
    }, 500);
  };

  // Hàm mở khóa nội dung
  window.unlockContent = function() {
    lockedOverlay.style.display = "none";
    lockedContent.style.display = "block";
    alert("🎉 Content unlocked! Enjoy reading.");
  };
});
