// コメントを取得して表示する関数
function loadComments(projectId, commentsContainer) {
    fetch(`/api/comments?project_id=${projectId}`)
        .then(response => response.json())
        .then(data => {
            commentsContainer.innerHTML = data.map(comment => {
                const pictureUrl = comment.user.picture || 'https://www.gravatar.com/avatar/' + comment.user.email_hash + '?s=200&d=mp';
                const date = new Date(comment.created_at).toLocaleString();
                return '<div class="border rounded-lg p-4">' +
                       '  <div class="flex items-center">' +
                       '    <img class="h-8 w-8 rounded-full" src="' + pictureUrl + '" alt="">' +
                       '    <div class="ml-3">' +
                       '      <p class="text-sm font-medium text-gray-900">' + comment.user.name + '</p>' +
                       '      <p class="text-sm text-gray-500">' + date + '</p>' +
                       '    </div>' +
                       '  </div>' +
                       '  <div class="mt-2">' +
                       '    <p class="text-gray-600 whitespace-pre-wrap">' + comment.comment_text + '</p>' +
                       '  </div>' +
                       '</div>';
            }).join('');
        });
}

// コメントを投稿する関数
function postComment(projectId, commentText, commentsContainer) {
    fetch('/api/comments', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            project_id: projectId,
            comment_text: commentText
        })
    })
    .then(response => {
        if (response.ok) {
            document.getElementById('comment-text').value = '';
            loadComments(projectId, commentsContainer);
        }
    });
}
