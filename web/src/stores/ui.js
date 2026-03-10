import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useUiStore = defineStore('ui', () => {
  const loadingCount = ref(0)
  const errorMessage = ref('')

  function beginLoading() {
    loadingCount.value += 1
  }

  function endLoading() {
    loadingCount.value = Math.max(0, loadingCount.value - 1)
  }

  function showError(message) {
    errorMessage.value = message || 'Request failed'
  }

  function clearError() {
    errorMessage.value = ''
  }

  return { loadingCount, errorMessage, beginLoading, endLoading, showError, clearError }
})
