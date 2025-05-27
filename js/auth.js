// Kullanıcı girişi kontrolü ve modal gösterme fonksiyonu
function checkAuthAndShowModal(callback) {
    const token = localStorage.getItem('token');
    if (!token) {
        showLoginModal();
        return false;
    }
    if (callback) callback();
    return true;
}

// Favori ekleme/çıkarma işlemi
function toggleFavorite(recipeId) {
    if (!checkAuthAndShowModal()) return;
    
    const user = JSON.parse(localStorage.getItem('user'));
    if (!user) return;

    const favorites = JSON.parse(localStorage.getItem('favorites') || '[]');
    const index = favorites.indexOf(recipeId);

    if (index === -1) {
        favorites.push(recipeId);
        showToast('Tarif favorilere eklendi!', 'success');
    } else {
        favorites.splice(index, 1);
        showToast('Tarif favorilerden çıkarıldı!', 'info');
    }

    localStorage.setItem('favorites', JSON.stringify(favorites));
    updateFavoriteUI(recipeId);
}

// Favori durumuna göre UI güncelleme
function updateFavoriteUI(recipeId) {
    const favoriteBtn = document.querySelector(`[data-recipe-id="${recipeId}"]`);
    if (!favoriteBtn) return;

    const favorites = JSON.parse(localStorage.getItem('favorites') || '[]');
    const isFavorite = favorites.includes(recipeId);

    favoriteBtn.innerHTML = isFavorite ? 
        '<i class="fas fa-heart"></i> Favorilerden Çıkar' : 
        '<i class="far fa-heart"></i> Favorilere Ekle';
    favoriteBtn.classList.toggle('active', isFavorite);
}

// Sayfa yüklendiğinde favori durumlarını güncelle
document.addEventListener('DOMContentLoaded', () => {
    const favoriteButtons = document.querySelectorAll('.favorite-btn');
    favoriteButtons.forEach(btn => {
        const recipeId = btn.dataset.recipeId;
        if (recipeId) {
            updateFavoriteUI(recipeId);
        }
    });
}); 