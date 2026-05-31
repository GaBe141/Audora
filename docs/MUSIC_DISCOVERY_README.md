# 🎵 Audora - Comprehensive Music Discovery System

A powerful, multi-platform music discovery and trend analysis system that monitors Gen Z and Gen Alpha music consumption patterns across TikTok, YouTube, Instagram, Twitter, Reddit, Tumblr, and more.

## 🚀 Features

### 📱 **Multi-Platform Discovery**
- **TikTok**: Track viral sounds, hashtag trends, and dance challenges
- **YouTube**: Monitor trending music videos and YouTube Shorts
- **Instagram**: Analyze Reels music usage and Story music stickers
- **Twitter**: Track music buzz, trending hashtags, and real-time conversations
- **Reddit**: Monitor music subreddits and community discussions
- **Tumblr**: Discover music aesthetics and cultural trends
- **SoundCloud**: Find emerging artists before they hit mainstream

### 📊 **Advanced Analytics**
- **Viral Progression Tracking**: Monitor how songs spread across platforms
- **Cross-Platform Analysis**: Identify songs trending on multiple platforms
- **Demographic Insights**: Understand age group preferences and regional trends
- **Predictive Analytics**: Forecast which songs will go viral next
- **Statistical Forecasting**: ARIMA, SARIMA, and ML models for trend prediction

### 🔮 **Trend Prediction**
- **Viral Candidates**: Identify songs likely to go viral in the next 7-14 days
- **Platform Momentum**: Track which platforms are driving discovery
- **Underground to Mainstream**: Monitor songs moving from niche to popular
- **Genre Evolution**: Analyze how music styles and genres are changing

### 📈 **Real-Time Monitoring**
- **Continuous Discovery**: Automated monitoring with customizable intervals
- **Rate Limit Management**: Smart API usage to avoid suspensions
- **Real-Time Alerts**: Notifications for sudden viral spikes
- **Historical Analysis**: Long-term trend tracking and pattern recognition

## 🛠️ Installation

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/audora.git
cd audora

# Run the setup script
python setup.py
```

### Manual Installation
```bash
# Install dependencies
pip install aiohttp aiofiles pandas numpy matplotlib seaborn plotly scikit-learn statsmodels darts requests python-dotenv

# Create directory structure
mkdir -p config data logs exports

# Copy configuration template
cp .env.template .env
```

## 🔑 API Configuration

### Required APIs for Full Functionality

#### 1. **TikTok Research API** (Primary)
```
URL: https://developers.tiktok.com/
Importance: ⭐⭐⭐⭐⭐ (Essential for Gen Z trends)
Cost: Free tier available
```

#### 2. **YouTube Data API v3** (Essential)
```
URL: https://console.developers.google.com/
Importance: ⭐⭐⭐⭐⭐ (Essential for video content)
Cost: Free with quotas
```

#### 3. **Twitter API v2** (Important)
```
URL: https://developer.twitter.com/
Importance: ⭐⭐⭐⭐ (Real-time buzz tracking)
Cost: Free tier available
```

#### 4. **Instagram Basic Display API** (Recommended)
```
URL: https://developers.facebook.com/
Importance: ⭐⭐⭐ (Visual content trends)
Cost: Free
```

#### 5. **Reddit API** (Valuable)
```
URL: https://www.reddit.com/prefs/apps
Importance: ⭐⭐⭐ (Community insights)
Cost: Free
```

#### 6. **Tumblr API** (Nice to Have)
```
URL: https://www.tumblr.com/oauth/apps
Importance: ⭐⭐ (Aesthetic trends)
Cost: Free
```

### Configuration Methods

#### Method 1: Environment Variables (.env file)
```bash
# Copy template and edit
cp .env.template .env
nano .env

# Add your credentials
TIKTOK_API_KEY=your_api_key_here
YOUTUBE_API_KEY=your_api_key_here
TWITTER_BEARER_TOKEN=your_token_here
# ... etc
```

#### Method 2: Interactive Setup
```bash
python src/api_config.py
```

#### Method 3: Configuration File
```bash
# Edit the JSON configuration
nano config/api_template.json
```

## 🎯 Usage

### Quick Start
```bash
# Run the main application
python src/music_discovery_app.py

# Follow the interactive menu:
# 1. Run single discovery scan
# 2. View API status
# 3. Generate analytics report
# 4. Start continuous monitoring
# 5. Configure APIs
# 6. Exit
```

### Individual Components

#### Discovery Engine
```bash
# Run social media discovery
python src/social_discovery_engine.py

# Run extended platform discovery
python src/extended_platforms.py
```

#### Statistical Analysis
```bash
# Run statistical analysis tests
python test_statistical_analysis.py

# Run trending schema tests
python src/trending_schema.py
```

#### API Management
```bash
# Configure and test APIs
python src/api_config.py
```

### Programmatic Usage

```python
from src.music_discovery_app import ComprehensiveMusicDiscoveryApp
import asyncio

# Initialize the app
app = ComprehensiveMusicDiscoveryApp()

# Run a discovery scan
async def discover_music():
    results = await app.run_full_discovery("US")
    print(f"Found {results['total_songs']} songs")

    # Save report
    report_path = app.save_discovery_report(results)
    print(f"Report saved to: {report_path}")

# Run discovery
asyncio.run(discover_music())
```

## 📊 Output & Reports

### Discovery Reports
```json
{
  "timestamp": "2024-01-15T10:30:00",
  "region": "US",
  "mainstream_platforms": {
    "total_songs_discovered": 127,
    "platform_discoveries": {
      "tiktok": 45,
      "youtube": 38,
      "instagram": 24,
      "twitter": 20
    },
    "multi_platform_hits": 12
  },
  "underground_platforms": {
    "total_underground_songs": 89,
    "platform_discoveries": {
      "reddit": 34,
      "soundcloud": 28,
      "tumblr": 27
    }
  },
  "cross_platform_analysis": {
    "cross_platform_hits": 8,
    "viral_progression": [...],
    "breakthrough_predictions": [...]
  },
  "recommendations": [
    "TikTok is currently the primary discovery platform",
    "Strong cross-platform activity detected",
    "12 emerging songs detected - perfect for early adoption"
  ]
}
```

### Trending Predictions
```json
{
  "next_viral_candidates": [
    {
      "artist": "Ice Spice",
      "song": "Think U The Shit",
      "platform": "tiktok",
      "momentum": 2500,
      "prediction": "Likely to go viral in 7-14 days"
    }
  ],
  "timeline_predictions": {
    "next_24_hours": "Monitor TikTok for viral spikes",
    "next_week": "5 songs predicted to gain traction",
    "next_month": "Cross-platform validation expected"
  }
}
```

## 📈 Analytics Features

### Real-Time Monitoring
- **Continuous Discovery**: Runs every 4 hours (configurable)
- **Multi-Region Support**: US, UK, Canada, Australia, and more
- **Rate Limit Management**: Automatic throttling to avoid API suspensions
- **Error Handling**: Robust error recovery and logging

### Statistical Analysis
- **Time Series Forecasting**: ARIMA, SARIMA models for trend prediction
- **Machine Learning**: Random Forest, Linear Regression for pattern detection
- **Data Quality Analysis**: Missing value detection, outlier identification
- **Seasonal Pattern Recognition**: Weekly, monthly trend identification

### Visualization
- **Trend Charts**: Line charts showing viral progression
- **Platform Comparison**: Bar charts comparing platform performance
- **Geographic Heatmaps**: Regional popularity visualization
- **Correlation Matrices**: Cross-platform relationship analysis

## 🔧 Advanced Configuration

### Custom Monitoring Intervals
```python
# Run continuous monitoring every 2 hours
await app.run_continuous_monitoring(
    interval_hours=2,
    regions=["US", "GB", "CA", "AU"]
)
```

### Rate Limit Customization
```json
{
  "tiktok": {
    "requests_per_minute": 60,
    "requests_per_hour": 1000,
    "requests_per_day": 10000
  }
}
```

### Platform Priority Settings
```python
# Prioritize certain platforms
priority_platforms = ["tiktok", "youtube", "instagram"]
discovery_results = await engine.discover_emerging_music(
    region="US",
    priority_platforms=priority_platforms
)
```

## 🚨 Troubleshooting

### Common Issues

#### 1. API Credential Errors
```bash
# Check API status
python src/api_config.py

# Test individual APIs
python -c "from src.social_discovery_engine import TikTokMusicAPI; print('TikTok API working')"
```

#### 2. Rate Limit Exceeded
```bash
# Check current usage
python -c "
from src.api_config import SocialAPIManager
manager = SocialAPIManager()
status = manager.get_status_report()
print(status)
"
```

#### 3. Missing Dependencies
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Or run setup again
python setup.py
```

#### 4. Import Errors
```bash
# Check Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Or add to your script
import sys
sys.path.append('src')
```

### Debug Mode
```bash
# Run with verbose logging
export DEBUG=1
python src/music_discovery_app.py
```

## 📋 Project Structure

```
spotify-insights/
├── src/
│   ├── music_discovery_app.py      # Main application
│   ├── social_discovery_engine.py  # Core discovery engine
│   ├── extended_platforms.py       # Reddit, Tumblr, SoundCloud APIs
│   ├── api_config.py              # API configuration management
│   ├── trending_schema.py          # Trend analysis framework
│   ├── statistical_analysis.py    # Statistical forecasting
│   └── ...
├── config/
│   ├── social_api_config.json     # API configurations (ignored; contains secrets)
│   └── api_template.json          # Configuration template
├── data/
│   ├── reports/                   # Generated reports
│   ├── trending/                  # Trending data
│   └── exports/                   # Exported datasets
├── tests/
│   ├── test_statistical_analysis.py
│   └── ...
├── setup.py                       # Setup script
├── requirements.txt              # Python dependencies
└── README.md                     # This file
```

## 🔮 Future Enhancements

### Planned Features
- **Spotify Integration**: Direct playlist creation from discoveries
- **AI-Powered Predictions**: Enhanced ML models for trend forecasting
- **Real-Time Dashboard**: Web interface for live monitoring
- **Automated Playlisting**: Auto-generate playlists from viral trends
- **Artist Collaboration Tools**: Connect emerging artists with opportunities

### Additional Platform Integrations
- **Shazam API**: Real-world music discovery patterns
- **Last.fm**: Scrobbling data and user preferences
- **Bandcamp**: Independent artist discovery
- **Apple Music**: iOS-specific trends
- **Twitch**: Gaming and streaming music usage

## 🤝 Contributing

We welcome contributions! Areas where help is needed:

1. **New Platform Integrations**: Add support for additional social platforms
2. **Enhanced Analytics**: Improve statistical models and predictions
3. **Visualization**: Create better charts and dashboards
4. **Testing**: Add more comprehensive test coverage
5. **Documentation**: Improve setup guides and API documentation

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/yourusername/spotify-insights.git
cd spotify-insights

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: Check this README and inline code documentation
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join conversations in GitHub Discussions
- **Email**: contact@spotify-insights.com (if available)

## 🙏 Acknowledgments

- **Spotify**: For the original inspiration and Web API
- **Social Media Platforms**: For providing APIs that make this analysis possible
- **Open Source Community**: For the amazing libraries that power this system
- **Music Industry**: For creating the amazing content we analyze

---

**Ready to discover the next viral hit? 🎵**

Start by running `python setup.py` and dive into the world of music trend analysis!
