# Example only: a deliberately weak image build
FROM node:latest AS build
WORKDIR /src
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node
ENV NODE_ENV=production \
    STRIPE_API_KEY=sk_live_FAKEFAKEFAKEFAKE0000
ARG DB_PASSWORD=hunter2-not-real
ADD https://downloads.example.test/agent.tar.gz /opt/agent.tar.gz
RUN curl -fsSL https://get.example.test/install.sh | sh
RUN pip install --trusted-host pypi.example.test example-agent==1.2.0
COPY --from=build /src/dist /app
CMD ["node", "/app/server.js"]
