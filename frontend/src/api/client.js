import axios from 'axios';
import { io } from 'socket.io-client';

const API_BASE_URL = '/api';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const socket = io('http://localhost:5000', {
  autoConnect: true,
  reconnection: true,
});
