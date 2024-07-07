import { Column, Entity, PrimaryColumn, PrimaryGeneratedColumn } from 'typeorm';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn()
  id: number;
  @Column()
  username: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;
}
