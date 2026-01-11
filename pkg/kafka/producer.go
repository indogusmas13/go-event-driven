package kafka

import (
	"context"
	"encoding/json"
	"fmt"

	"go-event-driven/pkg/logger"

	"github.com/segmentio/kafka-go"
)

type Producer struct {
	writer *kafka.Writer
}

type Event struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

type UserRegisteredEvent struct {
	UserID    uint   `json:"user_id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role"`
}

func NewProducer(brokers []string) *Producer {
	writer := &kafka.Writer{
		Addr:     kafka.TCP(brokers...),
		Balancer: &kafka.LeastBytes{},
	}

	return &Producer{writer: writer}
}

func (p *Producer) PublishEvent(ctx context.Context, topic string, event Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	message := kafka.Message{
		Topic: topic,
		Value: payload,
	}

	if err := p.writer.WriteMessages(ctx, message); err != nil {
		logger.GetLogger().WithError(err).Error("Failed to publish event")
		return fmt.Errorf("failed to write message: %w", err)
	}

	logger.GetLogger().WithField("topic", topic).WithField("event_type", event.Type).Info("Event published successfully")
	return nil
}

func (p *Producer) Close() error {
	return p.writer.Close()
}