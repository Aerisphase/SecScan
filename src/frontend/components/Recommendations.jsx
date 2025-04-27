import React from 'react';
import { Card, Typography, Tag, Button, Space } from 'antd';
import { LinkOutlined } from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;

const Recommendations = ({ recommendations }) => {
  if (!recommendations || recommendations.length === 0) {
    return null;
  }

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'high':
        return 'red';
      case 'medium':
        return 'orange';
      case 'low':
        return 'green';
      default:
        return 'blue';
    }
  };

  const openDocumentation = (vulnerabilityType) => {
    const vulnType = vulnerabilityType.toLowerCase().replace(' ', '-');
    window.open(`https://owasp.org/www-community/attacks/${vulnType}`, '_blank');
  };

  return (
    <div className="recommendations-container">
      <Title level={3}>Security Recommendations</Title>
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        {recommendations.map((rec, index) => (
          <Card key={index} className="recommendation-card">
            <Space direction="vertical" size="small">
              <div className="recommendation-header">
                <Title level={4}>{rec.vulnerability_type}</Title>
                <Tag color={getSeverityColor(rec.severity)}>
                  {rec.severity}
                </Tag>
                <Tag color="blue">
                  Confidence: {(rec.similarity_score * 100).toFixed(1)}%
                </Tag>
              </div>
              
              <Paragraph>
                <Text strong>Description: </Text>
                {rec.description}
              </Paragraph>
              
              <Paragraph>
                <Text strong>Recommendation: </Text>
                {rec.recommendation}
              </Paragraph>
              
              <Button
                type="link"
                icon={<LinkOutlined />}
                onClick={() => openDocumentation(rec.vulnerability_type)}
              >
                Learn More
              </Button>
            </Space>
          </Card>
        ))}
      </Space>
    </div>
  );
};

export default Recommendations; 